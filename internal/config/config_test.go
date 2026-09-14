package config

import (
	"net/url"
	"testing"
)

// 口令里出现 @ : / ? # 这类字符时，字符串拼接会拼出非法 DSN 或连错主机；
// 这条用例用"最难缠"的口令固定住转义行为。
func TestBuildDSNEscapesCredentials(t *testing.T) {
	t.Setenv("DB_HOST", "db.internal")
	t.Setenv("DB_PORT", "6543")
	t.Setenv("DB_NAME", "metafusion_db")
	t.Setenv("DB_USER", "metafusion")
	t.Setenv("DB_PASSWORD", "p@ss:w/rd?x#1")
	t.Setenv("DB_SSLMODE", "require")

	parsed, err := url.Parse(buildDSN())
	if err != nil {
		t.Fatalf("拼出的 DSN 不是合法 URL: %v", err)
	}
	if parsed.Scheme != "postgres" {
		t.Fatalf("scheme = %s", parsed.Scheme)
	}
	if parsed.Host != "db.internal:6543" {
		t.Fatalf("host = %s", parsed.Host)
	}
	if parsed.Path != "/metafusion_db" {
		t.Fatalf("path = %s", parsed.Path)
	}
	pass, _ := parsed.User.Password()
	if parsed.User.Username() != "metafusion" || pass != "p@ss:w/rd?x#1" {
		t.Fatalf("凭据转义不正确: user=%s pass=%s", parsed.User.Username(), pass)
	}
	if parsed.Query().Get("sslmode") != "require" {
		t.Fatalf("sslmode = %s", parsed.Query().Get("sslmode"))
	}
}
