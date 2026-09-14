// Package testutil 提供"需要真实 PostgreSQL 才运行"的测试入口。
//
// 与主仓库 backend/internal/testutil 同一语义：没有环境变量就跳过，
// 因此本地与 CI 默认不依赖数据库；切流前可以用它跑一次真实回归。
// 连接串必须指向**独立测试库**（库名含 _test），避免误连线上库。
package testutil

import (
	"context"
	"database/sql"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	_ "github.com/lib/pq"
)

const envKey = "STORAGE_TEST_DSN"

// DSN 返回测试库连接串；未设置时跳过用例。
func DSN(t *testing.T) string {
	t.Helper()
	dsn := strings.TrimSpace(os.Getenv(envKey))
	if dsn == "" {
		t.Skip(envKey + " 未设置：跳过需要真实数据库的用例")
	}
	parsed, err := url.Parse(dsn)
	if err != nil || !strings.Contains(parsed.Path, "_test") {
		t.Fatalf("%s 必须指向独立测试库（库名需含 _test）：%s", envKey, dsn)
	}
	return dsn
}

// Database 返回测试库连接（用完自动关闭）。
func Database(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("postgres", DSN(t))
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err = db.PingContext(ctx); err != nil {
		db.Close()
		t.Fatalf("ping: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}
