package handler

import (
	"mime"
	"strings"
	"testing"

	"github.com/MoeclubM/metafusion-storage/internal/auth"
	"github.com/MoeclubM/metafusion-storage/internal/store"
)

// 绑定用途是有限字段码空间：空值走默认，非法码必须拒绝而不是静默落库。
func TestNormalizeRole(t *testing.T) {
	cases := map[string]string{
		"":               defaultRole,
		"track_audio":    "track_audio",
		"  DISC_IMAGE  ": "disc_image",
		"Bad-Role":       "",
		"1track":         "",
		"a":              "a",
		"track_audio_2":  "track_audio_2",
	}
	for in, want := range cases {
		if got := normalizeRole(in); got != want {
			t.Fatalf("normalizeRole(%q) = %q, 期望 %q", in, got, want)
		}
	}
}

// 只有上传者本人或持 storage.asset.moderate 的审核者可以完成/绑定/解绑文件。
// S01 起老令牌不再凭 admin 角色管理他人文件（审核码无角色兜底），仅保留历史上传边界。
func TestCanManageAsset(t *testing.T) {
	owner := &auth.Principal{ID: "u1", Role: "user"}
	moderator := &auth.Principal{ID: "u2", Role: "user", Permissions: []string{"storage.asset.moderate"}}
	legacyAdmin := &auth.Principal{ID: "u3", Role: "admin"}
	revokedAdmin := &auth.Principal{ID: "u4", Role: "admin", Permissions: []string{"community.post.create"}}
	other := &auth.Principal{ID: "u5", Role: "editor"}
	if !canManageAsset(owner, "u1") {
		t.Fatal("上传者应可管理自己的文件")
	}
	if !canManageAsset(moderator, "u1") {
		t.Fatal("持 storage.asset.moderate 的成员应可管理他人文件")
	}
	if canManageAsset(legacyAdmin, "u1") {
		t.Fatal("S01 起老令牌的 admin 也不得凭角色管理他人文件")
	}
	if !legacyAdmin.Can(auth.PermissionAssetUpload) {
		t.Fatal("老令牌仍保留历史上传边界")
	}
	if canManageAsset(revokedAdmin, "u1") {
		t.Fatal("后台收回权限组后，admin 角色不得再管理他人文件")
	}
	if canManageAsset(other, "u1") {
		t.Fatal("无关用户不应可管理他人文件")
	}
	if canManageAsset(nil, "u1") {
		t.Fatal("匿名不应可管理文件")
	}
}

// X01 读聚合去重：多 ID 查询回来的同一绑定只保留一次；挂在新旧两 ID 上的
// 两条绑定是两行事实，不合并（A→C、B→C、C→D 从 D 读到全部且无重复即靠它守住形状）。
func TestDedupeFileBindings(t *testing.T) {
	mk := func(bindingID, target string) store.FileBinding {
		return store.FileBinding{Binding: store.Binding{ID: bindingID, AssetID: "asset-" + bindingID, TargetEntityID: target}}
	}
	in := []store.FileBinding{mk("b1", "a"), mk("b2", "c"), mk("b1", "a"), mk("b3", "c")}
	got := dedupeFileBindings(in)
	if len(got) != 3 {
		t.Fatalf("去重后应为 3 条，实际 %d", len(got))
	}
	seen := map[string]bool{}
	for _, f := range got {
		if seen[f.ID] {
			t.Fatalf("重复绑定 %s 未去重", f.ID)
		}
		seen[f.ID] = true
	}
	if got := dedupeFileBindings(nil); len(got) != 0 {
		t.Fatalf("空输入应返回空，实际 %v", got)
	}
}

// 下载响应头必须编码文件名：引号能改写 disposition 的其它参数，
// 下载响应头必须编码文件名：引号、控制字符与非 ASCII 都不能裸奔
// 下载响应头必须编码文件名：引号、控制字符与非 ASCII 都不能裸奔
// （本地模式下文件名完全由上传者提供，见 initiateUpload 的 file_name）。
func TestContentDispositionEncodesFileName(t *testing.T) {
	if got := contentDisposition(""); got != "attachment" {
		t.Fatalf("空文件名应退化成裸 attachment：%q", got)
	}
	if got := contentDisposition("track.flac"); got != "attachment; filename=track.flac" {
		t.Fatalf("普通文件名应原样带出：%q", got)
	}
	for _, name := range []string{"a\"; filename=\"evil.exe", "日本語.flac", "line\r\nbreak.flac", "back\\slash.flac"} {
		got := contentDisposition(name)
		// 换行会截断响应头（响应拆分），任何编码下都不能出现。
		if strings.ContainsAny(got, "\r\n") {
			t.Fatalf("响应头含控制字符：%q -> %q", name, got)
		}
		// 非 ASCII 必须走 filename*（RFC 2231）的百分号编码，不能是裸字节。
		for _, r := range got {
			if r > 127 {
				t.Fatalf("响应头含裸非 ASCII 字节：%q -> %q", name, got)
			}
		}
		// 最关键的判据：按标准解析回来必须只得到一个 attachment 与原名，
		// 名字里的引号/分号不得变成第二个参数。
		mediatype, params, err := mime.ParseMediaType(got)
		if err != nil {
			t.Fatalf("响应头无法解析：%q -> %q (%v)", name, got, err)
		}
		if mediatype != "attachment" || len(params) != 1 || params["filename"] != name {
			t.Fatalf("文件名往返不符：%q -> %q -> %v", name, got, params)
		}
	}
}
