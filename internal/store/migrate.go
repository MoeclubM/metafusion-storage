package store

import (
	"context"
	"embed"
	"fmt"
	"log"
	"sort"
	"strings"
)

// migrations/ 是表结构的唯一来源：启动时按文件名（版本号）顺序应用尚未记账的版本。
//
// 用 go:embed 而不是读磁盘：镜像里只有二进制（Dockerfile 只拷 /app/storage-server），
// 迁移文件必须随二进制走，否则新实例启动时无文件可用。
//
//go:embed migrations/*.sql
var migrationFS embed.FS

// migrationLockKey 是迁移期间的事务级 advisory lock 键。这里刻意用一个与目录服务
// （740202）、账号服务（740203）都不同的键：多副本同时启动时只让一个实例执行 DDL，
// 其余实例等它提交后再查账本，避免两条 CREATE TABLE 撞在 pg_type 的唯一索引上。
const migrationLockKey = 740204

// ledgerDDL 是版本账本自身：它不能依赖任何迁移文件（storage schema 要到 000001 才存在），
// 因此先于账本检查执行。与 000001 里的 CREATE SCHEMA 重复是无害的——两条都幂等。
const ledgerDDL = `CREATE SCHEMA IF NOT EXISTS storage;
CREATE TABLE IF NOT EXISTS storage.schema_migrations(
  version text PRIMARY KEY,
  applied_at timestamptz NOT NULL DEFAULT now()
);`

type migration struct {
	version string
	sql     string
}

// loadMigrations 读嵌入的迁移文件并按版本号排序：顺序即执行顺序，
// 文件名前缀（000001…）就是版本号，改文件名等于改历史。
func loadMigrations() ([]migration, error) {
	entries, err := migrationFS.ReadDir("migrations")
	if err != nil {
		return nil, err
	}
	out := make([]migration, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".up.sql") {
			continue
		}
		body, err := migrationFS.ReadFile("migrations/" + e.Name())
		if err != nil {
			return nil, err
		}
		out = append(out, migration{version: strings.TrimSuffix(e.Name(), ".up.sql"), sql: string(body)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].version < out[j].version })
	return out, nil
}

// Migrate 应用尚未记账的迁移，返回本次应用的版本号（已是最新时返回空切片）。
//
// 每个版本一个事务：DDL 与账本一起提交，不会出现"结构变了但没记账"。
// 迁移文件本身幂等，因此重复启动、多副本并发都不会改结构（并发由 advisory lock 串行化）。
func (s *Store) Migrate(ctx context.Context) ([]string, error) {
	if _, err := s.db.ExecContext(ctx, ledgerDDL); err != nil {
		return nil, err
	}
	all, err := loadMigrations()
	if err != nil {
		return nil, err
	}
	applied := []string{}
	for _, m := range all {
		did, err := s.applyMigration(ctx, m)
		if err != nil {
			return applied, err
		}
		if did {
			log.Printf("storage: applied schema migration %s", m.version)
			applied = append(applied, m.version)
		}
	}
	return applied, nil
}

// applyMigration 在一个事务里取锁、重查账本、执行 DDL、记账，返回这一版是否真的被应用。
// 取锁后重查是必需的：等锁期间另一个实例可能已经把同一版应用了，此时必须空转，
// 否则会重复执行 DDL（幂等语句本身安全，但账本插入会撞主键）。
func (s *Store) applyMigration(ctx context.Context, m migration) (bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, "SELECT pg_advisory_xact_lock($1)", migrationLockKey); err != nil {
		return false, err
	}
	var done bool
	if err = tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM storage.schema_migrations WHERE version=$1)", m.version).Scan(&done); err != nil {
		return false, err
	}
	if done {
		return false, nil
	}
	if _, err = tx.ExecContext(ctx, m.sql); err != nil {
		return false, fmt.Errorf("apply migration %s: %w", m.version, err)
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO storage.schema_migrations(version) VALUES($1)", m.version); err != nil {
		return false, err
	}
	if err = tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
}
