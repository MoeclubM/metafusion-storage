package audit

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
)

// capture 是本包用例的假写入端：把落库的行收集起来断言，不依赖数据库。
type capture struct {
	mu      sync.Mutex
	entries []Entry
	err     error
}

func (c *capture) write(_ context.Context, e Entry) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = append(c.entries, e)
	return c.err
}

func (c *capture) all() []Entry {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]Entry, len(c.entries))
	copy(out, c.entries)
	return out
}

// TestRecorderPrepareFillsDefaults：service / id / occurred_at / result / changes 的默认值都补齐。
func TestRecorderPrepareFillsDefaults(t *testing.T) {
	cap := &capture{}
	rec := newTestRecorder(ServiceName, 4, cap.write, nil)
	defer rec.Close()
	if err := rec.RecordSync(context.Background(), Entry{Action: "asset.upload_initiated"}); err != nil {
		t.Fatalf("RecordSync: %v", err)
	}
	got := cap.all()
	if len(got) != 1 {
		t.Fatalf("应写出一行，实际 %d", len(got))
	}
	e := got[0]
	if e.Service != ServiceName {
		t.Fatalf("service 应补成 %s，实际 %q", ServiceName, e.Service)
	}
	if _, err := uuid.Parse(e.ID); err != nil {
		t.Fatalf("id 应是 uuid: %q (%v)", e.ID, err)
	}
	if e.OccurredAt.IsZero() || time.Since(e.OccurredAt) > time.Minute {
		t.Fatalf("occurred_at 应是当前时间: %v", e.OccurredAt)
	}
	if e.Result != "success" {
		t.Fatalf("result 缺省应为 success: %q", e.Result)
	}
	if e.Changes == nil || len(e.Changes) != 0 {
		t.Fatalf("changes 缺省应为空对象: %#v", e.Changes)
	}
}

// TestRecorderSanitizesBeforeWrite：脱敏在写入器这一层无条件执行（调用点忘了也兜得住）。
func TestRecorderSanitizesBeforeWrite(t *testing.T) {
	cap := &capture{}
	rec := newTestRecorder(ServiceName, 4, cap.write, nil)
	defer rec.Close()
	rec.Record(Entry{Action: "binding.created", Changes: map[string]any{"token": "abc", "email": "jane@x.com"}})
	rec.Close()
	got := cap.all()
	if len(got) != 1 {
		t.Fatalf("应写出一行，实际 %d", len(got))
	}
	if got[0].Changes["token"] != redacted || got[0].Changes["email"] != "j***@x.com" {
		t.Fatalf("写入器未脱敏: %#v", got[0].Changes)
	}
}

// TestRecorderTruncatesUserAgent：UA 截断到契约规定的 512 字符。
func TestRecorderTruncatesUserAgent(t *testing.T) {
	cap := &capture{}
	rec := newTestRecorder(ServiceName, 4, cap.write, nil)
	defer rec.Close()
	rec.Record(Entry{Action: "binding.created", ActorUserAgent: strings.Repeat("u", 4096)})
	rec.Close()
	got := cap.all()
	if len(got) != 1 {
		t.Fatalf("应写出一行，实际 %d", len(got))
	}
	if n := len([]rune(got[0].ActorUserAgent)); n != MaxUserAgentLen {
		t.Fatalf("UA 应截断到 %d 字符，实际 %d", MaxUserAgentLen, n)
	}
}

// TestRecorderQueueFullDoesNotBlock：队列满时 Record 立刻返回并计入丢弃，绝不等待业务请求。
func TestRecorderQueueFullDoesNotBlock(t *testing.T) {
	release := make(chan struct{})
	var wrote atomic.Int64
	write := func(ctx context.Context, _ Entry) error {
		select {
		case <-release:
		case <-ctx.Done():
			return ctx.Err()
		}
		wrote.Add(1)
		return nil
	}
	var releaseOnce sync.Once
	free := func() { releaseOnce.Do(func() { close(release) }) }
	// 队列容量 1 + 写入端阻塞：只有"丢弃"这一条路能让 Record 立刻返回。
	rec := newTestRecorder(ServiceName, 1, write, nil)
	defer func() {
		free()
		rec.Close()
	}()
	started := time.Now()
	for i := 0; i < 500; i++ {
		rec.Record(Entry{Action: "asset.upload_initiated", RequestID: fmt.Sprintf("req-%d", i)})
	}
	elapsed := time.Since(started)
	if elapsed > time.Second {
		t.Fatalf("队列满时 Record 阻塞了 %s：必须丢弃而不是等待", elapsed)
	}
	if dropped := rec.Dropped(); dropped < 498 {
		t.Fatalf("队列满应大量计入丢弃（1 条被消费 + 1 条在队列，其余丢弃），实际丢弃 %d", dropped)
	}
	free()
	rec.Close()
	if wrote.Load() < 1 {
		t.Fatalf("排空后应至少写出一行，实际 %d", wrote.Load())
	}
}

// TestRecorderRecordAfterCloseCountsAsDropped：Close 之后的 Record 不 panic、不计入已写。
func TestRecorderRecordAfterCloseCountsAsDropped(t *testing.T) {
	cap := &capture{}
	rec := newTestRecorder(ServiceName, 4, cap.write, nil)
	rec.Record(Entry{Action: "binding.created"})
	rec.Close()
	before := len(cap.all())
	rec.Record(Entry{Action: "binding.created"})
	if len(cap.all()) != before {
		t.Fatal("停止后的 Record 不该再写库")
	}
	if rec.Dropped() != 1 {
		t.Fatalf("停止后的 Record 应计入丢弃，实际 %d", rec.Dropped())
	}
}

// TestRecorderWriteFailureOnlyLogs：落库失败只记日志并丢这一行，不 panic、不回滚业务。
func TestRecorderWriteFailureOnlyLogs(t *testing.T) {
	var mu sync.Mutex
	logs := []string{}
	logf := func(format string, args ...any) {
		mu.Lock()
		defer mu.Unlock()
		logs = append(logs, fmt.Sprintf(format, args...))
	}
	cap := &capture{err: errors.New("db down")}
	rec := newTestRecorder(ServiceName, 4, cap.write, logf)
	rec.Record(Entry{Action: "asset.upload_completed", RequestID: "req-1"})
	rec.Close()
	mu.Lock()
	defer mu.Unlock()
	if len(logs) != 1 || !strings.Contains(logs[0], "落库失败") {
		t.Fatalf("写失败应打一条错误日志，实际 %v", logs)
	}
}

// TestRecorderRecordSyncReportsError：同步写把错误返回给调用方（测试与强一致动作靠它判定）。
func TestRecorderRecordSyncReportsError(t *testing.T) {
	cap := &capture{err: errors.New("db down")}
	rec := newTestRecorder(ServiceName, 4, cap.write, func(string, ...any) {})
	defer rec.Close()
	if err := rec.RecordSync(context.Background(), Entry{Action: "binding.created"}); err == nil {
		t.Fatal("写失败时 RecordSync 应返回错误")
	}
	if rec.Dropped() != 0 {
		t.Fatalf("同步写不计入丢弃，实际 %d", rec.Dropped())
	}
}

// TestRecorderNilSafe：nil 记录器不 panic（服务里"没接线"与"接错线"要能区分，但不能崩）。
func TestRecorderNilSafe(t *testing.T) {
	var rec *Recorder
	rec.Record(Entry{Action: "binding.created"})
	rec.Close()
	if rec.Dropped() != 0 {
		t.Fatalf("nil 记录器丢弃数应为 0，实际 %d", rec.Dropped())
	}
	if err := rec.RecordSync(context.Background(), Entry{}); err == nil {
		t.Fatal("nil 记录器的同步写应返回错误")
	}
}

// TestNewRecorderWithoutDBKeepsServing：接不到库时（db 为 nil）记录器仍能用，只是每行写失败。
func TestNewRecorderWithoutDBKeepsServing(t *testing.T) {
	rec := NewRecorder(nil, ServiceName)
	if rec.service != ServiceName {
		t.Fatalf("service 应记住: %q", rec.service)
	}
	if rec.Dropped() != 0 {
		t.Fatal("新记录器不应有丢弃")
	}
	rec.Record(Entry{Action: "binding.created"})
	rec.Close()
}
