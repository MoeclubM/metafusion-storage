package handler

import (
	"testing"

	"github.com/MoeclubM/metafusion-storage/internal/auth"
	"github.com/MoeclubM/metafusion-storage/internal/config"
	"github.com/MoeclubM/metafusion-storage/internal/store"
)

// 配额判定口径：并发看 pending 计数，容量看 complete 真实字节 + pending 声明 + 本次声明。
func TestQuotaCheck(t *testing.T) {
	cfg := config.Config{UserQuotaMB: 100, SiteQuotaMB: 1000, UserConcurrentUploads: 2, SiteConcurrentUploads: 10}
	mb := int64(1) << 20
	cases := []struct {
		name       string
		u, site    store.Usage
		size       int64
		wantCode   string
		wantStatus int
	}{
		{"empty passes", store.Usage{}, store.Usage{}, 10 * mb, "", 0},
		{"user concurrent hit", store.Usage{PendingCount: 2}, store.Usage{}, mb, "too_many_uploads", 429},
		{"site concurrent hit", store.Usage{}, store.Usage{PendingCount: 10}, mb, "too_many_uploads", 429},
		{"user quota hit", store.Usage{CompleteBytes: 90 * mb}, store.Usage{}, 20 * mb, "quota_exceeded", 413},
		{"pending counts as budget", store.Usage{PendingBytes: 95 * mb}, store.Usage{}, 10 * mb, "quota_exceeded", 413},
		{"site quota hit", store.Usage{}, store.Usage{CompleteBytes: 999 * mb}, 2 * mb, "quota_exceeded", 413},
		{"exact fit passes", store.Usage{CompleteBytes: 90 * mb}, store.Usage{}, 10 * mb, "", 0},
	}
	for _, c := range cases {
		if code, status := quotaCheck(c.u, c.site, c.size, cfg); code != c.wantCode || status != c.wantStatus {
			t.Fatalf("%s: quotaCheck = (%q,%d), want (%q,%d)", c.name, code, status, c.wantCode, c.wantStatus)
		}
	}
	// 全零配置（默认）永远放行：不启用预算时 initiate 行为与此前一致。
	if code, status := quotaCheck(store.Usage{CompleteBytes: 1 << 40}, store.Usage{PendingCount: 1 << 20}, 1<<40, config.Config{}); code != "" || status != 0 {
		t.Fatalf("零配置应放行一切，实际 (%q,%d)", code, status)
	}
}

// 被禁发的文件不对无权者出现在列表里；上传者本人与审核者仍可见（与 readable 同口径）。
func TestFilterBlocked(t *testing.T) {
	mk := func(id, uploader string, blocked bool) store.FileBinding {
		return store.FileBinding{
			Binding: store.Binding{ID: "b-" + id, AssetID: "a-" + id},
			Asset:   store.Asset{ID: "a-" + id, UploaderID: uploader, Blocked: blocked},
		}
	}
	in := []store.FileBinding{mk("1", "u1", false), mk("2", "u1", true), mk("3", "u2", true)}
	if got := filterBlocked(in, nil); len(got) != 1 || got[0].ID != "b-1" {
		t.Fatalf("匿名应只看到未禁发，实际 %v", got)
	}
	owner := &auth.Principal{ID: "u1"}
	if got := filterBlocked(in, owner); len(got) != 2 {
		t.Fatalf("上传者应看到自己的被禁发，实际 %d 条", len(got))
	}
	moderator := &auth.Principal{ID: "u9", Permissions: []string{auth.PermissionAssetModerate}}
	if got := filterBlocked(in, moderator); len(got) != 3 {
		t.Fatalf("审核者应看到全部，实际 %d 条", len(got))
	}
	other := &auth.Principal{ID: "u3"}
	if got := filterBlocked(in, other); len(got) != 1 {
		t.Fatalf("无关用户应只看到未禁发，实际 %d 条", len(got))
	}
}
