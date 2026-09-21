package maintenance

import (
	"testing"
	"time"
)

// 缺失标记的熔断口径：零星缺失才标记；有读错、或缺失多且占比过半（像整桶不可用）时只上报。
func TestShouldMarkMissing(t *testing.T) {
	cases := []struct {
		name                   string
		missing, checked, errs int
		want                   bool
	}{
		{"no missing", 0, 100, 0, false},
		{"nothing checked", 0, 0, 0, false},
		{"few missing", 2, 100, 0, true},
		{"single missing", 1, 1, 0, true},
		{"read errors abort", 2, 100, 1, false},
		{"mass missing aborts", 60, 100, 0, false},
		{"below count threshold still marks", 4, 5, 0, true},
		{"exact half marks", 5, 10, 0, true},
		{"over half aborts", 6, 10, 0, false},
	}
	for _, c := range cases {
		if got := shouldMarkMissing(c.missing, c.checked, c.errs); got != c.want {
			t.Fatalf("%s: shouldMarkMissing(%d,%d,%d) = %v, want %v",
				c.name, c.missing, c.checked, c.errs, got, c.want)
		}
	}
}

// 键检查：只有落在声明 sha 前缀下的键才能动；空值、前缀不符一律不动。
func TestKeyMatchesSHA(t *testing.T) {
	sha := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	good := "objects/01/" + sha + "/track.flac"
	if !keyMatchesSHA(good, sha) {
		t.Fatalf("正常内容寻址键应通过：%s", good)
	}
	for name, tc := range map[string]struct{ key, sha string }{
		"empty key":      {"", sha},
		"empty sha":      {good, ""},
		"wrong sha":      {"objects/01/" + sha + "/x", "ff" + sha[2:]},
		"wrong prefix":   {"objects/99/" + sha + "/x", sha},
		"outside tree":   {"uploads/" + sha, sha},
		"quarantine key": {"quarantine/objects/01/" + sha + "/x", sha},
	} {
		if keyMatchesSHA(tc.key, tc.sha) {
			t.Fatalf("%s 应判为不匹配：key=%q", name, tc.key)
		}
	}
}

// 回收资格纯条件：过期、无绑定、pending、非禁发才进候选（SQL 已表达，这里固定边界语义）。
func TestPendingExpiredBoundary(t *testing.T) {
	now := time.Now()
	lease := now.Add(-time.Minute)
	if !pendingExpired(nil, now.Add(-72*time.Hour), now, 72*time.Hour) {
		t.Fatal("NULL 租约的存量行应按 created_at + 默认 TTL 兜底")
	}
	if pendingExpired(nil, now.Add(-time.Hour), now, 72*time.Hour) {
		t.Fatal("72 小时内的存量行不应回收")
	}
	if !pendingExpired(&lease, now.Add(-time.Hour), now, 72*time.Hour) {
		t.Fatal("租约已过期的行应回收")
	}
	fresh := now.Add(time.Hour)
	if pendingExpired(&fresh, now.Add(-100*time.Hour), now, 72*time.Hour) {
		t.Fatal("租约未到期的行不应回收，即使创建时间很老")
	}
}
