package audit

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"
)

// TestSanitizeChangesRedactsSecretKeys：键名黑名单（精确 + 子串，大小写不敏感）一律 [redacted]。
func TestSanitizeChangesRedactsSecretKeys(t *testing.T) {
	in := map[string]any{
		"password": "hunter2", "Old_Password": "x", "new_password": "y", "password_hash": "z",
		"token": "t", "access_token": "t2", "refresh_token": "t3", "token_hash": "t4",
		"secret": "s", "client_secret": "s2", "secret_hash": "s3",
		"authorization": "Bearer abc", "cookie": "mf_session=abc", "api_key": "k", "code_verifier": "cv",
		// 子串命中：含 password / secret / token / hash 的键名同样要脱敏
		"user_token_value": "t5", "legacyHash": "h", "s3_secret_key": "s4",
		"binding_role": "track_audio",
	}
	out := SanitizeChanges(in)
	blacklisted := []string{"password", "Old_Password", "new_password", "password_hash",
		"token", "access_token", "refresh_token", "token_hash",
		"secret", "client_secret", "secret_hash",
		"authorization", "cookie", "api_key", "code_verifier",
		"user_token_value", "legacyHash", "s3_secret_key"}
	for _, k := range blacklisted {
		if out[k] != redacted {
			t.Fatalf("键 %q 应被替换成 %s，实际 %v", k, redacted, out[k])
		}
	}
	if out["binding_role"] != "track_audio" {
		t.Fatalf("非敏感键不应被改写：%v", out["binding_role"])
	}
	// 脱敏产出一份新 map，不修改入参（调用方还要继续用原值走业务）。
	if in["password"] != "hunter2" {
		t.Fatalf("SanitizeChanges 不该修改入参：%v", in["password"])
	}
}

// TestSanitizeChangesRecurses：嵌套 map / 数组 / 未知类型都走同一套规则，且结果一定可序列化。
func TestSanitizeChangesRecurses(t *testing.T) {
	in := map[string]any{
		"asset":  map[string]any{"sha256": "abc", "user_token": "nested"},
		"before": map[string]string{"password": "p", "status": "pending"},
		"parts":  []any{map[string]any{"secret": "s"}, "plain"},
		"names":  []string{"a", "b"},
		"bytes":  []byte{0x01, 0x02, 0x03},
	}
	out := SanitizeChanges(in)
	asset, ok := out["asset"].(map[string]any)
	if !ok || asset["sha256"] != "abc" || asset["user_token"] != redacted {
		t.Fatalf("嵌套 map 脱敏不符: %#v", out["asset"])
	}
	before, ok := out["before"].(map[string]any)
	if !ok || before["password"] != redacted || before["status"] != "pending" {
		t.Fatalf("map[string]string 脱敏不符: %#v", out["before"])
	}
	parts, ok := out["parts"].([]any)
	if !ok || len(parts) != 2 {
		t.Fatalf("数组应保持形状: %#v", out["parts"])
	}
	if inner, ok := parts[0].(map[string]any); !ok || inner["secret"] != redacted {
		t.Fatalf("数组元素内的敏感键未脱敏: %#v", parts[0])
	}
	if got, ok := out["bytes"].(string); !ok || got != "<3 bytes>" {
		t.Fatalf("原始字节只应留长度: %v", out["bytes"])
	}
	if _, err := json.Marshal(out); err != nil {
		t.Fatalf("脱敏结果应可序列化: %v", err)
	}
}

// TestSanitizeChangesMasksEmails：值里夹带的邮箱、键名含 email 的字段，都不能带完整邮箱落库。
func TestSanitizeChangesMasksEmails(t *testing.T) {
	in := map[string]any{
		"file_name":       "invoice jane.doe@example.com.bin",
		"email":           "jane@example.com",
		"contact_email":   "JANE@Example.COM",
		"malformed_email": "not-an-email",
		"empty_email":     "",
		"two":             "a@b.co and c@d.org",
	}
	out := SanitizeChanges(in)
	if got := out["file_name"]; got != "invoice j***@example.com.bin" {
		t.Fatalf("值里的邮箱应被遮罩: %v", got)
	}
	if got := out["email"]; got != "j***@example.com" {
		t.Fatalf("email 键的值应被遮罩: %v", got)
	}
	if got := out["contact_email"]; got != "J***@Example.COM" {
		t.Fatalf("含 email 的键名同样遮罩: %v", got)
	}
	if got := out["malformed_email"]; got != "n***" {
		t.Fatalf("键名说是邮箱就必须遮罩: %v", got)
	}
	if got := out["empty_email"]; got != "" {
		t.Fatalf("空值保持空: %q", got)
	}
	if got := out["two"]; got != "a***@b.co and c***@d.org" {
		t.Fatalf("同一值里的多个邮箱都要遮罩: %v", got)
	}
	// 与真库用例同一判据：序列化后的文本里不得再出现完整邮箱。
	body, err := json.Marshal(out)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if m := emailPattern.FindAllString(string(body), -1); len(m) != 0 {
		t.Fatalf("审计摘要里不该有完整邮箱: %v", m)
	}
}

// TestMaskEmail 固定公开 helper 的形状：它是跨服务一致的对外约定，改形状等于改契约。
func TestMaskEmail(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"jane.doe@example.com", "j***@example.com"},
		{"a@b.co", "a***@b.co"},
		{"no-at-sign", "no-at-sign"},
		{"@nolocal.com", "@nolocal.com"},
		{"trailing@", "trailing@"},
		{"", ""},
	} {
		if got := MaskEmail(tc.in); got != tc.want {
			t.Fatalf("MaskEmail(%q) = %q, 期望 %q", tc.in, got, tc.want)
		}
	}
}

// TestMaskSecret：邀请码一类准凭据保留前 4 位；短值只留 1 位，不把整串写进审计。
func TestMaskSecret(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"abcd1234", "abcd…"},
		{"abcd", "a…"},
		{"ab", "a…"},
		{"", ""},
	} {
		if got := MaskSecret(tc.in); got != tc.want {
			t.Fatalf("MaskSecret(%q) = %q, 期望 %q", tc.in, got, tc.want)
		}
	}
}

// TestSanitizeChangesTruncatesStrings：单个字符串值按字符截断，多字节字符不能被切成非法 UTF-8。
func TestSanitizeChangesTruncatesStrings(t *testing.T) {
	out := SanitizeChanges(map[string]any{"file_name": strings.Repeat("a", 4096)})
	if got := out["file_name"].(string); len([]rune(got)) != MaxStringLen {
		t.Fatalf("字符串应截断到 %d 字符，实际 %d", MaxStringLen, len([]rune(got)))
	}
	wide := SanitizeChanges(map[string]any{"file_name": strings.Repeat("汉", 2000)})
	got := wide["file_name"].(string)
	if len([]rune(got)) != MaxStringLen {
		t.Fatalf("多字节字符也应截到 %d 字符，实际 %d", MaxStringLen, len([]rune(got)))
	}
	if !utf8.ValidString(got) {
		t.Fatalf("截断不能切出非法 UTF-8: %q", got)
	}
	if _, err := json.Marshal(wide); err != nil {
		t.Fatalf("截断结果应可序列化: %v", err)
	}
}

// TestSanitizeChangesTruncatesOversized：整份摘要超过上限时按 key 丢弃并打 _truncated 标记。
func TestSanitizeChangesTruncatesOversized(t *testing.T) {
	in := map[string]any{}
	for i := 0; i < 200; i++ {
		in["field_"+strconv.Itoa(i)] = strings.Repeat("v", 200)
	}
	out := SanitizeChanges(in)
	body, err := json.Marshal(out)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if len(body) > MaxChangesBytes {
		t.Fatalf("摘要应截断到 %d 字节以内，实际 %d", MaxChangesBytes, len(body))
	}
	if out[truncatedKey] != true {
		t.Fatalf("超限摘要必须带 %s 标记: %#v", truncatedKey, out)
	}
	if len(out) >= len(in) {
		t.Fatalf("超限时应丢弃部分键：%d -> %d", len(in), len(out))
	}
	// 确定性：同样的输入丢同样的键（排障时不会出现"同样操作留下不同摘要"）。
	again := SanitizeChanges(in)
	if len(again) != len(out) {
		t.Fatalf("同样的输入应丢同样的键: %d vs %d", len(again), len(out))
	}
}
