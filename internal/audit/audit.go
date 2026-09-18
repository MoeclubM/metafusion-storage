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

// Schema 是契约 §1 的 DDL 逐字复制（18 列 + 4 条索引），只多了一层**存在性守卫**：
// 整段包在 DO 块里，先 to_regclass('audit.audit_log') 判表是否存在，不存在才建。
//
// 为什么必须守卫（部署实测踩到的坑，不是风格偏好）：PostgreSQL 的 CREATE INDEX IF NOT EXISTS
// 会**先做表的所有权检查、再看索引是否已存在**，而 CREATE TABLE IF NOT EXISTS 只要求 schema 的 CREATE。
// 审计表由部署时的角色（任务 A 的 mf_audit_owner）预建，四个服务的运行角色都不是它的 owner——
// 旧版无条件执行 CREATE INDEX IF NOT EXISTS 的四个服务启动即 42501 must be owner of table audit_log，
// 全部起不来；反过来不预建、让某一个服务先建，其余三个也全挂。守卫后表已存在的实例上是纯空转，
// 不触发任何所有权检查（真实库负向验证见 internal/store 的 TestAuditDDLRequiresNoTableOwnership）。
//
// 它同时是迁移文件 internal/store/migrations/000002_audit_log.up.sql 的内容，
// schema_test.go 断言两者逐字相同：表结构只能有一份（迁移文件），
// 这里留一份是为了让"审计包自带契约"可读、也让形状断言不依赖数据库。
const Schema = `DO $audit_ddl$
BEGIN
  PERFORM pg_advisory_xact_lock(740205);
  IF to_regclass('audit.audit_log') IS NULL THEN
    CREATE SCHEMA IF NOT EXISTS audit;
    CREATE TABLE audit.audit_log (
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
    CREATE INDEX audit_log_occurred_at_idx ON audit.audit_log(occurred_at DESC);
    CREATE INDEX audit_log_service_action_idx ON audit.audit_log(service, action, occurred_at DESC);
    CREATE INDEX audit_log_actor_idx ON audit.audit_log(actor_user_id, occurred_at DESC);
    CREATE INDEX audit_log_target_idx ON audit.audit_log(target_type, target_id, occurred_at DESC);
  END IF;
END
$audit_ddl$;
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
