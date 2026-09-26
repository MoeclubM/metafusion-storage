package handler

import (
	"sort"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/MoeclubM/metafusion-storage/internal/auth"
	"github.com/MoeclubM/metafusion-storage/internal/catalog"
	"github.com/MoeclubM/metafusion-storage/internal/config"
	"github.com/MoeclubM/metafusion-storage/internal/objects"
	"github.com/MoeclubM/metafusion-storage/internal/store"
)

// frozenRoutes 是存储服务的对外契约（见 metafusion-docs 的 docs/api-storage.md）：
// 内容寻址直传 + 绑定用途 + 统一下载入口。改动路由会在这里失败。
var frozenRoutes = []string{
	"DELETE /api/storage/bindings/:id",
	"GET /api/storage/assets/:id",
	"GET /api/storage/assets/:id/content",
	"GET /api/storage/download/:assetId",
	"GET /api/storage/entities/:id/files",
	"GET /api/storage/moderation/blocked",
	"GET /api/storage/stats",
	"POST /api/storage/assets/:id/block",
	"POST /api/storage/assets/:id/unblock",
	"POST /api/storage/bind",
	"POST /api/storage/upload/complete",
	"POST /api/storage/upload/initiate",
	"POST /api/storage/verify-hash",
	"PUT /api/storage/upload/stream/:assetId",
}

func TestRoutesMatchFrozenContract(t *testing.T) {
	gin.SetMode(gin.TestMode)
	verifier, err := auth.New(config.Config{JWTIssuer: "https://findverse.cc/api", JWTAudience: "metafusion"})
	if err != nil {
		t.Fatalf("verifier: %v", err)
	}
	r := gin.New()
	New(&store.Store{}, &objects.Store{}, catalog.New(""), verifier, config.Config{}).Register(r)
	got := []string{}
	for _, route := range r.Routes() {
		got = append(got, route.Method+" "+route.Path)
	}
	sort.Strings(got)
	want := append([]string{}, frozenRoutes...)
	sort.Strings(want)
	if len(got) != len(want) {
		t.Fatalf("路由数量 = %d, 期望 %d\n实际:\n%s", len(got), len(want), join(got))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("第 %d 条不一致：实际 %s / 期望 %s\n实际全集:\n%s", i, got[i], want[i], join(got))
		}
	}
}

func join(items []string) string {
	out := ""
	for _, s := range items {
		out += s + "\n"
	}
	return out
}
