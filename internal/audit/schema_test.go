package audit

import (
	"os"
	"reflect"
	"strings"
	"testing"
)

// migrationPath 是存储服务的审计迁移落点（契约 §6.1：internal/store/migrations/00000N_audit_log.up.sql）。
const migrationPath = "../store/migrations/000002_audit_log.up.sql"

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

// TestSchemaShape：契约 §1 的列、约束、索引、锁键一个不少（跨服务契约，改动必须是有意的）。
func TestSchemaShape(t *testing.T) {
	columns := []string{
		"id", "occurred_at", "service", "action", "actor_user_id", "actor_username",
		"credential_type", "actor_ip", "actor_user_agent", "target_type", "target_id",
		"changes", "result", "error_code", "request_method", "route", "http_status", "request_id",
	}
	for _, col := range columns {
		if !strings.Contains(Schema, "\n  "+col+" ") {
			t.Fatalf("审计表缺少列 %q", col)
		}
	}
	// 列数与 Entry 字段数必须相等：少一列就意味着某个字段永远落不进库。
	if got := reflect.TypeOf(Entry{}).NumField(); got != len(columns) {
		t.Fatalf("Entry 字段数 %d 与表列数 %d 不一致", got, len(columns))
	}
	if !strings.Contains(Schema, "CREATE SCHEMA IF NOT EXISTS audit") {
		t.Fatal("缺少 CREATE SCHEMA IF NOT EXISTS audit")
	}
	if !strings.Contains(Schema, "CREATE TABLE IF NOT EXISTS audit.audit_log") {
		t.Fatal("缺少建表语句（必须幂等，多副本同时启动要能重复执行）")
	}
	if got := strings.Count(Schema, "CREATE INDEX IF NOT EXISTS"); got != 4 {
		t.Fatalf("契约 §1 规定 4 条索引，实际 %d", got)
	}
	if !strings.Contains(Schema, "CHECK (result IN ('success','failure'))") {
		t.Fatal("result 列的 CHECK 约束必须与契约一致")
	}
	// 建表锁键是跨服务共用的 740205；storage 自己的迁移锁是 740204（internal/store/migrate.go），
	// 两者不能写混：写混就会出现"以为串行化了、其实各锁各的"。
	if !strings.Contains(Schema, "pg_advisory_xact_lock(740205)") {
		t.Fatal("审计建表必须用契约规定的跨服务锁键 740205")
	}
	if strings.Contains(Schema, "740204") {
		t.Fatal("审计 DDL 不该出现 storage 自己的迁移锁键 740204")
	}
}
