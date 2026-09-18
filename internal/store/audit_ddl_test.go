package store

import (
	"context"
	"database/sql"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/MoeclubM/metafusion-storage/internal/testutil"
)

// shapeQuerier 让形状快照既能跑在 *sql.DB 上，也能跑在事务里
// （非 owner 用例必须在同一个会话/事务内取样，形状不变才是空转的证据）。
type shapeQuerier interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

const auditColumnsQuery = "SELECT column_name || ':' || data_type || ':' || is_nullable FROM information_schema.columns WHERE table_schema = 'audit' AND table_name = 'audit_log' ORDER BY ordinal_position"

const auditIndexesQuery = "SELECT indexname || ':' || indexdef FROM pg_indexes WHERE schemaname = 'audit' AND tablename = 'audit_log' ORDER BY indexname"

// auditDDL 读**嵌入的迁移文件**：测的就是服务启动时执行的那一份，不另抄一份来测。
func auditDDL(t *testing.T) string {
	t.Helper()
	body, err := migrationFS.ReadFile("migrations/000002_audit_log.up.sql")
	if err != nil {
		t.Fatalf("读迁移文件 migrations/000002_audit_log.up.sql: %v", err)
	}
	return string(body)
}

// auditShape 返回列与索引的形状快照（已排序，可直接比较）。
func auditShape(t *testing.T, q shapeQuerier) ([]string, []string) {
	t.Helper()
	ctx := context.Background()
	scan := func(query string) []string {
		rows, err := q.QueryContext(ctx, query)
		if err != nil {
			t.Fatalf("形状快照查询失败: %v", err)
		}
		defer rows.Close()
		out := []string{}
		for rows.Next() {
			var line string
			if err := rows.Scan(&line); err != nil {
				t.Fatalf("形状快照扫描失败: %v", err)
			}
			out = append(out, line)
		}
		if err := rows.Err(); err != nil {
			t.Fatalf("形状快照遍历失败: %v", err)
		}
		return out
	}
	return scan(auditColumnsQuery), scan(auditIndexesQuery)
}

// auditDB 打开库并应用迁移：审计表必须先存在，否则这两个用例测的不是"重复执行"。
func auditDB(t *testing.T) *sql.DB {
	t.Helper()
	db := testutil.Database(t)
	s, err := Open(context.Background(), testutil.DSN(t))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	if err := s.Init(context.Background()); err != nil {
		t.Fatalf("init schema: %v", err)
	}
	return db
}

// TestAuditDDLIsIdempotentAndRecreates 覆盖守卫的两条路径，全程在一个事务里、最后回滚：
//  1. 表已存在 → 整段 DDL 纯空转（列与索引一个字都不变）；
//  2. 表被删掉 → 重跑能重建出 18 列与 4 条索引 + 主键。
func TestAuditDDLIsIdempotentAndRecreates(t *testing.T) {
	db := auditDB(t)
	ctx := context.Background()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback()

	beforeCols, beforeIdx := auditShape(t, tx)
	if len(beforeCols) != 18 || len(beforeIdx) != 5 {
		t.Fatalf("前置形状不符（应 18 列 + 4 索引 + 主键）：%d 列 / %d 索引", len(beforeCols), len(beforeIdx))
	}
	if _, err := tx.ExecContext(ctx, auditDDL(t)); err != nil {
		t.Fatalf("表已存在时重跑 DDL 失败（应为纯空转）: %v", err)
	}
	afterCols, afterIdx := auditShape(t, tx)
	if strings.Join(beforeCols, "|") != strings.Join(afterCols, "|") || strings.Join(beforeIdx, "|") != strings.Join(afterIdx, "|") {
		t.Fatalf("空转不该改结构：\n列 before=%v after=%v\n索引 before=%v after=%v", beforeCols, afterCols, beforeIdx, afterIdx)
	}

	// 删表后重跑：守卫应走"建表 + 建四条索引"这条路径。
	if _, err := tx.ExecContext(ctx, "DROP TABLE audit.audit_log"); err != nil {
		t.Fatalf("drop table: %v", err)
	}
	if _, err := tx.ExecContext(ctx, auditDDL(t)); err != nil {
		t.Fatalf("表不存在时重跑 DDL 应重建，实际失败: %v", err)
	}
	rebuiltCols, rebuiltIdx := auditShape(t, tx)
	if strings.Join(rebuiltCols, "|") != strings.Join(beforeCols, "|") {
		t.Fatalf("重建后的列与契约不符：\nbefore=%v\nrebuilt=%v", beforeCols, rebuiltCols)
	}
	if strings.Join(rebuiltIdx, "|") != strings.Join(beforeIdx, "|") {
		t.Fatalf("重建后的索引与契约不符：\nbefore=%v\nrebuilt=%v", beforeIdx, rebuiltIdx)
	}
	// 重建后再跑一次仍然是空转（守卫是幂等的，不是"删了才建"）。
	if _, err := tx.ExecContext(ctx, auditDDL(t)); err != nil {
		t.Fatalf("重建后重跑 DDL 失败: %v", err)
	}
	againCols, againIdx := auditShape(t, tx)
	if strings.Join(againCols, "|") != strings.Join(rebuiltCols, "|") || strings.Join(againIdx, "|") != strings.Join(rebuiltIdx, "|") {
		t.Fatalf("重建后重跑不该改结构：%v / %v", againCols, againIdx)
	}

	if err := tx.Rollback(); err != nil {
		t.Fatalf("rollback: %v", err)
	}
}

// TestAuditDDLRequiresNoTableOwnership 是部署阻塞项的回归守卫：
// 审计表由部署时的角色（任务 A 的 mf_audit_owner）预建，四个服务的运行角色都**不是**它的 owner。
// PostgreSQL 的 CREATE INDEX IF NOT EXISTS 会先做表的所有权检查、再看索引是否已存在，
// 因此旧版无条件 DDL 会让非 owner 的实例在启动执行迁移时直接
// 42501 must be owner of table audit_log（四个服务全挂）。守卫后表已存在的实例上是纯空转。
//
// 这里用 SET ROLE 扮成"非 owner 运行角色"重跑整段 DDL，并用旧版形状做负向对照。
func TestAuditDDLRequiresNoTableOwnership(t *testing.T) {
	db := auditDB(t)
	ctx := context.Background()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback()

	// 角色名随机且带固定前缀：用例之间/并发实例之间不会撞名（角色与授权都在本事务里回滚）。
	role := "mf_audit_probe_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := tx.ExecContext(ctx, "CREATE ROLE "+role+" NOINHERIT"); err != nil {
		t.Skipf("测试库用户不能建角色（%v）：跳过非 owner 回归；请在超级用户下跑一次以覆盖部署阻塞项", err)
	}
	for _, grant := range []string{
		"GRANT USAGE, CREATE ON SCHEMA audit TO " + role,
		"GRANT SELECT, INSERT ON audit.audit_log TO " + role,
	} {
		if _, err := tx.ExecContext(ctx, grant); err != nil {
			t.Fatalf("%s: %v", grant, err)
		}
	}
	if _, err := tx.ExecContext(ctx, "SET ROLE "+role); err != nil {
		t.Fatalf("SET ROLE %s: %v", role, err)
	}

	beforeCols, beforeIdx := auditShape(t, tx)
	if _, err := tx.ExecContext(ctx, auditDDL(t)); err != nil {
		t.Fatalf("非 owner 运行角色重跑审计 DDL 失败（线上就是四个服务启动全挂的那个错误）: %v", err)
	}
	afterCols, afterIdx := auditShape(t, tx)
	if strings.Join(beforeCols, "|") != strings.Join(afterCols, "|") || strings.Join(beforeIdx, "|") != strings.Join(afterIdx, "|") {
		t.Fatalf("非 owner 下的空转改了结构：%v / %v", afterCols, afterIdx)
	}

	// 负向对照：旧版形状（无守卫 + CREATE INDEX IF NOT EXISTS）在同一角色下必须 42501，
	// 否则说明这条守卫并不是必需的，结论要重新审。
	legacy := "CREATE TABLE IF NOT EXISTS audit.audit_log (id uuid PRIMARY KEY);\n" +
		"CREATE INDEX IF NOT EXISTS audit_log_probe_legacy_idx ON audit.audit_log(id);"
	if _, err := tx.ExecContext(ctx, legacy); err == nil {
		t.Fatal("非 owner 角色执行无守卫的旧版 DDL 竟然成功：请重新核实 42501 的结论")
	} else if !strings.Contains(err.Error(), "must be owner") {
		t.Fatalf("非 owner 执行旧版 DDL 应报 must be owner，实际: %v", err)
	} else {
		// 把根因的原始报错留在用例输出里：读这段日志的人不用自己复现就能看到 42501 的形状。
		t.Logf("旧版无守卫 DDL 在非 owner 角色下的报错（这就是四个服务启动失败的根因）：%v", err)
	}
	// 事务已因上一条失败而中止：交给 defer 的 Rollback 收尾（SET ROLE 会随之回滚）。
}
