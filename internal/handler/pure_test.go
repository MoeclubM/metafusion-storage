package handler

import (
	"testing"

	"github.com/MoeclubM/metafusion-storage/internal/auth"
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

// 只有上传者本人或管理员可以完成/绑定/解绑文件。
func TestCanManageAsset(t *testing.T) {
	owner := &auth.Principal{ID: "u1", Role: "editor"}
	admin := &auth.Principal{ID: "u2", Role: "admin"}
	other := &auth.Principal{ID: "u3", Role: "editor"}
	if !canManageAsset(owner, "u1") {
		t.Fatal("上传者应可管理自己的文件")
	}
	if !canManageAsset(admin, "u1") {
		t.Fatal("管理员应可管理他人文件")
	}
	if canManageAsset(other, "u1") {
		t.Fatal("无关用户不应可管理他人文件")
	}
	if canManageAsset(nil, "u1") {
		t.Fatal("匿名不应可管理文件")
	}
}
