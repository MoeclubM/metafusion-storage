// Package audit 是「所有修改操作增加审计留痕」（跨服务契约 docs/architecture/audit-log.md）
// 在存储服务侧的实现：可选的审计表 DDL + 一个非阻塞写入器 + 一个按动作码注册表触发的中间件。
//
// 四个服务各带一份**同源**代码（本服务的这一份就在 internal/audit）：四仓是独立 module、
// 没有跨仓依赖通道，因此不建共享模块，只保证函数名与语义一致，便于交叉审查。
//
// 三条硬约束（契约 §3）：
//   - 审计是**旁路**：入队不阻塞业务响应，落库失败只记日志、不回滚业务写入；
//   - 只有登记了动作码的写路由才写审计，GET 与豁免路由不写；
//   - 写入前必须脱敏（§4），审计行里不出现口令、令牌、完整邮箱。
package audit

import "time"

// ServiceName 是本服务写进 audit_log.service 的取值（契约 §1 的四个服务之一）。
const ServiceName = "storage"

// ErrorCodeKey 是请求上下文里存放稳定错误码的键：处理器用 Fail 写入，
// 中间件据此写 result=failure + error_code（错误码必须与响应体 error 字段一致）。
const ErrorCodeKey = "audit_error_code"

// credential_type 的取值（契约 §1）。存储只验签，只能区分 PAT 与会话（§7）：
// oauth / system 这两个值留给账号服务，本服务不产出。
const (
	CredentialSession   = "session"
	CredentialPAT       = "pat"
	CredentialAnonymous = "anonymous"
)

// Schema 是契约 §1 的 DDL **逐字复制**（含 CREATE SCHEMA / advisory lock / 建表 / 建索引）。
//
// 它同时是迁移文件 internal/store/migrations/000002_audit_log.up.sql 的内容，
// audit_schema_test.go 断言两者逐字相同：表结构只能有一份（迁移文件），
// 这里留一份是为了让"审计包自带契约"可读、也让形状断言不依赖数据库。
const Schema = `-- 审计表跨服务共用：四个服务的业务 DDL 各管自己的 schema，这里单独用 audit schema，
-- 因为它不属于任何单个服务的领域数据（见 §5 的取舍说明）。
CREATE SCHEMA IF NOT EXISTS audit;

-- 四个服务可能同时首次启动；建表用同一个 advisory 锁键（740205）串行化。
-- 一次 Exec 里的多条语句由 lib/pq 作为隐式事务批处理发送，xact 锁因此覆盖到建表结束。
SELECT pg_advisory_xact_lock(740205);

CREATE TABLE IF NOT EXISTS audit.audit_log (
  id               uuid PRIMARY KEY,
  occurred_at      timestamptz NOT NULL DEFAULT now(),
  service          text NOT NULL,
  action           text NOT NULL,
  actor_user_id    uuid,
  actor_username   text NOT NULL DEFAULT '',
  credential_type  text NOT NULL DEFAULT '',
  actor_ip         text NOT NULL DEFAULT '',
  actor_user_agent text NOT NULL DEFAULT '',
  target_type      text NOT NULL DEFAULT '',
  target_id        text NOT NULL DEFAULT '',
  changes          jsonb NOT NULL DEFAULT '{}'::jsonb,
  result           text NOT NULL DEFAULT 'success' CHECK (result IN ('success','failure')),
  error_code       text NOT NULL DEFAULT '',
  request_method   text NOT NULL DEFAULT '',
  route            text NOT NULL DEFAULT '',
  http_status      int NOT NULL DEFAULT 0,
  request_id       text NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS audit_log_occurred_at_idx ON audit.audit_log(occurred_at DESC);
CREATE INDEX IF NOT EXISTS audit_log_service_action_idx ON audit.audit_log(service, action, occurred_at DESC);
CREATE INDEX IF NOT EXISTS audit_log_actor_idx ON audit.audit_log(actor_user_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS audit_log_target_idx ON audit.audit_log(target_type, target_id, occurred_at DESC);
`

// Entry 是一条审计行。字段与契约 §1 的表列一一对应，顺序也一致（便于逐列核对）。
//
// ActorUserID 为空时落库为 NULL（uuid 列不接受空串）；Changes 为 nil 时落成 {}。
type Entry struct {
	ID             string
	OccurredAt     time.Time
	Service        string
	Action         string
	ActorUserID    string
	ActorUsername  string
	CredentialType string
	ActorIP        string
	ActorUserAgent string
	TargetType     string
	TargetID       string
	Changes        map[string]any
	Result         string
	ErrorCode      string
	RequestMethod  string
	Route          string
	HTTPStatus     int
	RequestID      string
}

// Detail 是被动对象与变更摘要：处理器用 Describe 交给中间件。
type Detail struct {
	TargetType string
	TargetID   string
	Changes    map[string]any
}

// Actor 是操作者身份快照。Username 落库是**快照**：账号改名/删号后审计仍可读（契约 §1）。
type Actor struct {
	UserID         string
	Username       string
	CredentialType string
}
