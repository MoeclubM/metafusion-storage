package audit

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// 脱敏与截断的硬性上限（契约 §4）。改这里等于改契约：审计行的体积与“不出敏感值”的判据都由它们定义。
const (
	// MaxUserAgentLen 是 actor_user_agent 的截断长度。
	MaxUserAgentLen = 512
	// MaxStringLen 是单个字符串值（含递归到底层的每一层）的截断长度。
	MaxStringLen = 512
	// MaxChangesBytes 是 changes 序列化后的字节上限，超限时按 key 丢弃并打 _truncated 标记。
	MaxChangesBytes = 8 << 10
	// maxDepth 是递归深度上限：changes 是我们自己构造的两三层摘要，
	// 更深的嵌套只可能来自异常输入，直接折叠而不是无限递归。
	maxDepth = 8
	// redacted 是命中黑名单的键的替换值。
	redacted = "[redacted]"
	// truncatedKey 是摘要被截断时追加的标记键。
	truncatedKey = "_truncated"
)

// emailPattern 是“完整邮箱”的判据：值里出现它就要遮罩，测试也用同形状正则断言库里零命中。
// 刻意写得比 RFC 保守：只认常见的 local@label(.label)+，避免把 sha256、版本号、路径误判成邮箱。
var emailPattern = regexp.MustCompile(`[A-Za-z0-9._%+\-]+@[A-Za-z0-9](?:[A-Za-z0-9\-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9\-]*[A-Za-z0-9])?)`)

// secretKeys 是键名精确黑名单（大小写不敏感）。
var secretKeys = map[string]bool{
	"password": true, "old_password": true, "new_password": true, "password_hash": true,
	"token": true, "access_token": true, "refresh_token": true, "token_hash": true,
	"secret": true, "client_secret": true, "secret_hash": true,
	"authorization": true, "cookie": true, "api_key": true, "code_verifier": true,
}

// secretKeySubstrings 是键名子串黑名单：含这些片段的键一律替换成 [redacted]。
var secretKeySubstrings = []string{"password", "secret", "token", "hash"}

// SanitizeChanges 递归脱敏 + 截断一个变更摘要，返回可直接落库（jsonb）的新 map。
//
// 中间件在入队前无条件调用它一次：即使某个调用点忘了脱敏，落库的也已经是脱敏结果。
// 它就地收缩传入的 map（丢弃超限键），但不会把敏感值留在里面——调用方不应再复用被丢弃的数据。
func SanitizeChanges(m map[string]any) map[string]any {
	if len(m) == 0 {
		return map[string]any{}
	}
	out, ok := sanitizeValue(m, 0).(map[string]any)
	if !ok || out == nil {
		out = map[string]any{}
	}
	return truncateChanges(out)
}

// MaskEmail 遮罩一个邮箱：保留首字母与域名，中间一律 ***（契约 §4 的 a***@domain）。
// 输入不像邮箱（没有 @ 或 @ 在首尾）时原样返回：调用方要么已经判过形状，要么不该调它。
func MaskEmail(s string) string {
	at := strings.LastIndex(s, "@")
	if at <= 0 || at == len(s)-1 {
		return s
	}
	local := []rune(s[:at])
	if len(local) == 0 {
		return s
	}
	return string(local[0]) + "***" + s[at:]
}

// MaskSecret 遮罩准凭据（邀请码一类）：保留前 4 位，其余用省略号收尾。
// 短于 4 位时只保留 1 位——“短到看不出前缀”的值不该被原样写进审计。
func MaskSecret(s string) string {
	r := []rune(s)
	switch {
	case len(r) == 0:
		return ""
	case len(r) <= 4:
		return string(r[:1]) + "…"
	default:
		return string(r[:4]) + "…"
	}
}

// sanitizeValue 递归处理任意值：字符串做邮箱遮罩 + 截断，map 按键名脱敏后继续递归，
// 其余类型按原样保留（数字/布尔/nil）或降级成字符串（时间、未知类型），
// 保证产出的 map 一定能被 json.Marshal（否则整行摘要会退化成 {}）。
func sanitizeValue(v any, depth int) any {
	if depth > maxDepth {
		return "[nested]"
	}
	switch t := v.(type) {
	case nil:
		return nil
	case string:
		return truncate(maskEmailsInText(t), MaxStringLen)
	case bool, int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64, float32, float64, json.Number:
		return v
	case time.Time:
		return t.UTC().Format(time.RFC3339)
	case []byte:
		// 原始字节不进审计行（可能是内容本身）：只留长度。
		return truncate("<"+strconv.Itoa(len(t))+" bytes>", MaxStringLen)
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			out[k] = sanitizeEntry(k, val, depth)
		}
		return out
	case map[string]string:
		out := make(map[string]any, len(t))
		for k, val := range t {
			out[k] = sanitizeEntry(k, val, depth)
		}
		return out
	case []any:
		out := make([]any, 0, len(t))
		for _, item := range t {
			out = append(out, sanitizeValue(item, depth+1))
		}
		return out
	case []string:
		out := make([]any, 0, len(t))
		for _, item := range t {
			out = append(out, sanitizeValue(item, depth+1))
		}
		return out
	default:
		return truncate(fmt.Sprintf("%v", t), MaxStringLen)
	}
}

// sanitizeEntry 按键名决定一个键值对怎么处理：黑名单键整体替换，邮箱键无条件遮罩，其余递归。
func sanitizeEntry(key string, val any, depth int) any {
	if redactKeyName(key) {
		return redacted
	}
	if strings.Contains(strings.ToLower(key), "email") {
		if s, ok := val.(string); ok {
			return truncate(maskEmailValue(s), MaxStringLen)
		}
	}
	return sanitizeValue(val, depth+1)
}

// redactKeyName 报告键名是否命中精确/子串黑名单（大小写不敏感）。
func redactKeyName(key string) bool {
	lower := strings.ToLower(key)
	if secretKeys[lower] {
		return true
	}
	for _, sub := range secretKeySubstrings {
		if strings.Contains(lower, sub) {
			return true
		}
	}
	return false
}

// maskEmailValue 遮罩“键名说明它就是邮箱”的值：没有 @ 的畸形值也不能原样落库。
func maskEmailValue(s string) string {
	if strings.Contains(s, "@") {
		return MaskEmail(s)
	}
	r := []rune(s)
	if len(r) == 0 {
		return s
	}
	return string(r[:1]) + "***"
}

// maskEmailsInText 把字符串里出现的完整邮箱逐个遮罩（值中夹带邮箱是常见形态，
// 例如 file_name = "invoice jane.doe@example.com.bin"）。
func maskEmailsInText(s string) string {
	if !strings.Contains(s, "@") {
		return s
	}
	return emailPattern.ReplaceAllStringFunc(s, MaskEmail)
}

// truncate 按**字符**截断（不是字节）：按字节切会把多字节字符切成非法 UTF-8，
// 而 jsonb 落库会直接拒绝非法编码。
func truncate(s string, max int) string {
	if max <= 0 || len(s) <= max {
		return s
	}
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return string(r[:max])
}

// truncateChanges 保证 changes 序列化后不超过上限：超限时按 key 排序从尾部逐个丢弃，
// 并打上 _truncated 标记。选“排序后丢尾部”而不是丢最大的：同样的输入必然丢同样的键，
// 排障时不会出现“两次同样的操作留下不同摘要”。
func truncateChanges(m map[string]any) map[string]any {
	if changesSize(m) <= MaxChangesBytes {
		return m
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		if k != truncatedKey {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	for i := len(keys) - 1; i >= 0; i-- {
		delete(m, keys[i])
		m[truncatedKey] = true
		if changesSize(m) <= MaxChangesBytes {
			return m
		}
	}
	return map[string]any{truncatedKey: true}
}

// changesSize 是摘要的序列化大小；序列化不了时返回一个“超限”值，
// 让 truncateChanges 继续丢弃键——最终要么能序列化，要么只剩 _truncated 标记。
func changesSize(m map[string]any) int {
	body, err := json.Marshal(m)
	if err != nil {
		return MaxChangesBytes + 1
	}
	return len(body)
}
