package audit

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
)

// 写入侧的可调参数（契约 §3）：队列容量 1024 是“业务突发时也不阻塞响应”的余量，
// 单行写入超时是“数据库卡住时不让后台 goroutine 一直挂在写操作上”的兜底。
const (
	queueSize    = 1024
	writeTimeout = 5 * time.Second
)

// insertSQL 是唯一的写入语句：列顺序与 Entry 字段一一对应。
const insertSQL = `INSERT INTO audit.audit_log (` +
	"id, occurred_at, service, action, actor_user_id, actor_username, credential_type," +
	" actor_ip, actor_user_agent, target_type, target_id, changes, result, error_code," +
	" request_method, route, http_status, request_id" +
	") VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)"

// Recorder 是审计写入器：一个有界队列 + 一个后台 goroutine。
//
// 为什么是异步：契约 §3 明确审计是旁路，业务成功但审计写失败只记日志、不回滚业务；
// 因此写库绝不能出现在响应路径上（数据库慢/抖动时会把所有写接口一起拖慢）。
type Recorder struct {
	db      *sql.DB
	service string
	queue   chan Entry
	write   func(context.Context, Entry) error
	logf    func(string, ...any)

	closing chan struct{}
	once    sync.Once
	wg      sync.WaitGroup

	stopped atomic.Bool
	dropped atomic.Int64
}

// NewRecorder 起一个后台写入器；service 写进每行的 service 列（本服务固定 audit.ServiceName）。
// db 为 nil 时入队的行会在写库时报错并丢弃——服务能启动，但审计不落库（调用方不该这么接）。
func NewRecorder(db *sql.DB, service string) *Recorder {
	r := &Recorder{
		db:      db,
		service: service,
		queue:   make(chan Entry, queueSize),
		logf:    log.Printf,
		closing: make(chan struct{}),
	}
	r.write = r.insert
	r.wg.Add(1)
	go r.run()
	return r
}

// newTestRecorder 只给本包测试用：注入写函数与队列容量，
// 让“队列满不阻塞”“落库失败只记日志”这两个语义在没有数据库时也能被固定住。
func newTestRecorder(service string, size int, write func(context.Context, Entry) error, logf func(string, ...any)) *Recorder {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	r := &Recorder{
		service: service,
		queue:   make(chan Entry, size),
		write:   write,
		logf:    logf,
		closing: make(chan struct{}),
	}
	r.wg.Add(1)
	go r.run()
	return r
}

// Record 非阻塞入队：队列满时打 error 日志并丢弃，**绝不等待**。
//
// 队列永不 close（Record 与 Close 可能并发），因此“已停止”用标志判定：
// 停止后到来的行计入丢弃数而不是 panic（send on closed channel）。
func (r *Recorder) Record(e Entry) {
	if r == nil {
		return
	}
	e = r.prepare(e)
	if r.stopped.Load() {
		r.dropped.Add(1)
		return
	}
	select {
	case r.queue <- e:
	default:
		r.dropped.Add(1)
		r.logf("audit: 队列已满，丢弃审计行 service=%s action=%s request_id=%s", e.Service, e.Action, e.RequestID)
	}
}

// RecordSync 同步写一行；仅测试与“必须强一致”的少数动作使用（契约 §3：本轮没有强一致动作）。
func (r *Recorder) RecordSync(ctx context.Context, e Entry) error {
	if r == nil {
		return errors.New("audit: nil recorder")
	}
	e = r.prepare(e)
	if err := r.write(ctx, e); err != nil {
		r.logf("audit: 同步写入失败 service=%s action=%s request_id=%s: %v", e.Service, e.Action, e.RequestID, err)
		return err
	}
	return nil
}

// Close 停止接收新行、排空队列并等后台 goroutine 退出（测试收尾用）。
// 可重复调用：第二次只是再等一次同一个 WaitGroup。
func (r *Recorder) Close() {
	if r == nil {
		return
	}
	r.once.Do(func() {
		r.stopped.Store(true)
		close(r.closing)
	})
	r.wg.Wait()
}

// Dropped 是丢弃行数（队列满或停止后入队）：测试断言“满队列不阻塞且丢行可观测”。
func (r *Recorder) Dropped() int64 {
	if r == nil {
		return 0
	}
	return r.dropped.Load()
}

// prepare 补齐契约 §1 的默认值，并**无条件**再脱敏一次 + 截断 UA。
// 放在这一层是因为它是所有写入路径（Record / RecordSync）的唯一收口点。
func (r *Recorder) prepare(e Entry) Entry {
	if e.Service == "" {
		e.Service = r.service
	}
	if e.ID == "" {
		e.ID = uuid.NewString()
	}
	if e.OccurredAt.IsZero() {
		e.OccurredAt = time.Now().UTC()
	}
	if e.Result == "" {
		e.Result = "success"
	}
	e.Changes = SanitizeChanges(e.Changes)
	e.ActorUserAgent = truncate(e.ActorUserAgent, MaxUserAgentLen)
	return e
}

// run 是后台消费循环：正常时逐条写库；收到关闭信号后把队列里剩下的排空再退出。
func (r *Recorder) run() {
	defer r.wg.Done()
	for {
		select {
		case e := <-r.queue:
			r.persist(e)
		case <-r.closing:
			for {
				select {
				case e := <-r.queue:
					r.persist(e)
				default:
					return
				}
			}
		}
	}
}

// persist 写一行：失败只记日志（审计不参与业务事务，丢一行比拖垮业务可接受）。
func (r *Recorder) persist(e Entry) {
	ctx, cancel := context.WithTimeout(context.Background(), writeTimeout)
	defer cancel()
	if err := r.write(ctx, e); err != nil {
		r.logf("audit: 落库失败，丢弃一行 service=%s action=%s request_id=%s: %v", e.Service, e.Action, e.RequestID, err)
	}
}

// insert 把 Entry 映射成一行 insert。
func (r *Recorder) insert(ctx context.Context, e Entry) error {
	if r.db == nil {
		return errors.New("audit: nil db")
	}
	body, err := json.Marshal(e.Changes)
	if err != nil {
		// 摘要序列化不了就降级成空对象：审计行本身（谁在什么时候做了什么）比摘要重要。
		body = []byte("{}")
	}
	// actor_user_id 是 uuid 列：空串不是合法 uuid，必须传 NULL。
	var actor any
	if e.ActorUserID != "" {
		actor = e.ActorUserID
	}
	_, err = r.db.ExecContext(ctx, insertSQL,
		e.ID, e.OccurredAt, e.Service, e.Action, actor, e.ActorUsername, e.CredentialType,
		e.ActorIP, e.ActorUserAgent, e.TargetType, e.TargetID, body, e.Result, e.ErrorCode,
		e.RequestMethod, e.Route, e.HTTPStatus, e.RequestID)
	return err
}
