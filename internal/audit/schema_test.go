package audit

import (
	"os"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

// migrationPath 是存储服务的审计迁移落点（契约 §6.1：internal/store/migrations/00000N_audit_log.up.sql）。
const migrationPath = "../store/migrations/000002_audit_log.up.sql"

// auditColumns 是契约 §1 的 18 列，顺序即建表顺序；值是该列的期望类型词。
var auditColumns = []struct {
	name string
	typ  string
}{
	{"id", "uuid"}, {"occurred_at", "timestamptz"}, {"service", "text"}, {"action", "text"},
	{"actor_user_id", "uuid"}, {"actor_username", "text"}, {"credential_type", "text"},
	{"actor_ip", "text"}, {"actor_user_agent", "text"}, {"target_type", "text"}, {"target_id", "text"},
	{"changes", "jsonb"}, {"result", "text"}, {"error_code", "text"}, {"request_method", "text"},
	{"route", "text"}, {"http_status", "int"}, {"request_id", "text"},
}

// tableBodyRe 取建表段。DDL 现在是 DO 块里的**守卫式**语句（顶层没有 CREATE TABLE IF NOT EXISTS 可解析），
// 所以从 "CREATE TABLE ... (" 取到 ");" 之间的内容再逐列核对。
var tableBodyRe = regexp.MustCompile("(?is)CREATE TABLE audit\\.audit_log\\s*\\((.*?)\\n\\s*\\);")

func tableBody(t *testing.T) string {
	t.Helper()
	m := tableBodyRe.FindStringSubmatch(Schema)
	if m == nil {
		t.Fatalf("从 Schema 里取不到建表段：守卫式 DDL 的形状变了？\n%s", Schema)
	}
	return m[1]
}

// TestSchemaMatchesMigrationFile：DDL 在这个仓库里有两份副本（本包常量 + 迁移文件），
// 它们必须逐字相同——迁移文件是表结构的唯一执行来源，常量是"审计包自带契约"的可读副本，
// 一旦漂移，读代码的人会按错误的列形状理解库里的数据。
func TestSchemaMatchesMigrationFile(t *testing.T) {
	raw, err := os.ReadFile(migrationPath)
	if err != nil {
		t.Fatalf("读迁移文件 %s: %v", migrationPath, err)
	}
	if string(raw) != Schema {
		t.Fatalf("%s 与 audit.Schema 不一致：迁移是唯一执行来源，改一处就要同步另一处\n--- 文件 ---\n%s\n--- 常量 ---\n%s", migrationPath, raw, Schema)
	}
}

// TestSchemaTableColumns：建表段的列名、顺序、类型与契约 §1 一致，列数等于 Entry 字段数。
func TestSchemaTableColumns(t *testing.T) {
	lines := []string{}
	for _, line := range strings.Split(tableBody(t), "\n") {
		if trimmed := strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(line), ",")); trimmed != "" {
			lines = append(lines, trimmed)
		}
	}
	if len(lines) != len(auditColumns) {
		t.Fatalf("建表段应有 %d 列，实际 %d 列：\n%s", len(auditColumns), len(lines), strings.Join(lines, "\n"))
	}
	for i, col := range auditColumns {
		fields := strings.Fields(lines[i])
		if len(fields) < 2 || fields[0] != col.name {
			t.Fatalf("第 %d 列应为 %s（顺序也是契约），实际 %q", i+1, col.name, lines[i])
		}
		if fields[1] != col.typ {
			t.Fatalf("列 %s 的类型应为 %s，实际 %q", col.name, col.typ, lines[i])
		}
	}
	// 列数与 Entry 字段数必须相等：少一列就意味着某个字段永远落不进库。
	if got := reflect.TypeOf(Entry{}).NumField(); got != len(auditColumns) {
		t.Fatalf("Entry 字段数 %d 与表列数 %d 不一致", got, len(auditColumns))
	}
	byLine := map[string]string{}
	for _, line := range lines {
		byLine[strings.Fields(line)[0]] = line
	}
	if !strings.Contains(byLine["occurred_at"], "DEFAULT now()") {
		t.Fatalf("occurred_at 应有 DEFAULT now(): %q", byLine["occurred_at"])
	}
	if !strings.Contains(byLine["changes"], "DEFAULT '{}'::jsonb") {
		t.Fatalf("changes 应有 DEFAULT '{}'::jsonb: %q", byLine["changes"])
	}
	if !strings.Contains(byLine["result"], "DEFAULT 'success'") || !strings.Contains(byLine["result"], "CHECK (result IN ('success','failure'))") {
		t.Fatalf("result 应有 success 默认值与取值域 CHECK: %q", byLine["result"])
	}
	if !strings.Contains(byLine["http_status"], "DEFAULT 0") {
		t.Fatalf("http_status 应有 DEFAULT 0: %q", byLine["http_status"])
	}
	// actor_user_id 必须可空：账号删了审计还得在（契约 §1 明确不建外键、允许 NULL）。
	if strings.Contains(byLine["actor_user_id"], "NOT NULL") {
		t.Fatalf("actor_user_id 必须可空: %q", byLine["actor_user_id"])
	}
}

// TestSchemaUsesExistenceGuard 是部署阻塞项的静态回归守卫：
// 四个服务的运行角色不是 audit.audit_log 的 owner（表由部署时的 mf_audit_owner 预建），
// 而 PostgreSQL 的 CREATE INDEX IF NOT EXISTS **先做所有权检查、再看索引是否已存在**，
// 于是旧版无条件 DDL 会让四个服务启动即 42501 must be owner of table audit_log。
// 因此：整段必须在 to_regclass 守卫内，索引不得再带 IF NOT EXISTS，锁仍在守卫内、建表之前取。
func TestSchemaUsesExistenceGuard(t *testing.T) {
	guard := "IF to_regclass('audit.audit_log') IS NULL THEN"
	if !strings.Contains(Schema, guard) {
		t.Fatalf("缺少存在性守卫 %q：非 owner 运行角色会因 CREATE INDEX 的所有权检查启动失败", guard)
	}
	if strings.Contains(Schema, "CREATE INDEX IF NOT EXISTS") {
		t.Fatal("索引不得再写 IF NOT EXISTS：它先做表所有权检查，非 owner 的启动/迁移会直接 42501")
	}
	if strings.Contains(Schema, "CREATE TABLE IF NOT EXISTS") {
		t.Fatal("建表不该再写 IF NOT EXISTS：已在 to_regclass 守卫内，两套存在性判定只会让人读错")
	}
	for _, idx := range []string{
		"audit_log_occurred_at_idx", "audit_log_service_action_idx",
		"audit_log_actor_idx", "audit_log_target_idx",
	} {
		if !strings.Contains(Schema, "CREATE INDEX "+idx+" ON audit.audit_log(") {
			t.Fatalf("缺少索引 %s（契约 §1 规定四条，且必须在守卫内创建）", idx)
		}
	}
	if got := strings.Count(Schema, "CREATE INDEX audit_log_"); got != 4 {
		t.Fatalf("契约 §1 规定 4 条索引，实际 %d", got)
	}
	if !strings.Contains(Schema, "PERFORM pg_advisory_xact_lock(740205)") {
		t.Fatal("审计建表必须用契约规定的跨服务锁键 740205，且用 PERFORM 放在守卫内")
	}
	if strings.Contains(Schema, "740204") {
		t.Fatal("审计 DDL 不该出现 storage 自己的迁移锁键 740204")
	}
	// 顺序：DO 块 → 取锁 → 判存在 → 建 schema/表/索引；锁必须在建表之前（并发首启只能一个建）。
	order := []string{"DO $audit_ddl$", "PERFORM pg_advisory_xact_lock(740205)", guard,
		"CREATE SCHEMA IF NOT EXISTS audit", "CREATE TABLE audit.audit_log (", "END IF;", "$audit_ddl$;"}
	at := -1
	for _, marker := range order {
		idx := strings.Index(Schema, marker)
		if idx <= at {
			t.Fatalf("DDL 片段 %q 缺失或顺序不对（应依次为 %v）", marker, order)
		}
		at = idx
	}
	// 整段必须是**一条** DO 语句：迁移 runner 是"整文件一次 Exec"，拆成多条会让守卫失去原子性。
	if !strings.HasPrefix(strings.TrimSpace(Schema), "DO $audit_ddl$") || !strings.HasSuffix(strings.TrimSpace(Schema), "$audit_ddl$;") {
		t.Fatalf("整段审计 DDL 必须是一条 DO $audit_ddl$ … $audit_ddl$; 语句：\n%s", Schema)
	}
}
