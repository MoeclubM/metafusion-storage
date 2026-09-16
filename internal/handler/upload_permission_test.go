package handler

import (
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/MoeclubM/metafusion-storage/internal/auth"
	"github.com/MoeclubM/metafusion-storage/internal/catalog"
	"github.com/MoeclubM/metafusion-storage/internal/config"
	"github.com/MoeclubM/metafusion-storage/internal/objects"
	"github.com/MoeclubM/metafusion-storage/internal/store"
)

// 上传与绑定按 storage.asset.upload 收口：登录且持有该码才进得了处理器，缺码一律 403 forbidden。
// 三个"看起来够用"的令牌都必须被拒——老令牌的 editor、只有论坛码的成员、以及**只有
// storage.asset.moderate 的审核者**：两个码是两件事（创建并登记自己的东西 vs 处置他人的东西），
// 互不蕴含，审核权不能代替上传权。
// 拒绝发生在触碰数据库之前，空库（&store.Store{}）足够判定；放行判据用"处理器给的 400"，
// 因为空载荷在闸门之后才会被校验。
func TestUploadRequiresUploadPermission(t *testing.T) {
	gin.SetMode(gin.TestMode)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	srv, kid := jwksServer(t, key)
	verifier := newVerifier(t, srv.URL)
	r := gin.New()
	New(&store.Store{}, &objects.Store{}, catalog.New(""), verifier, config.Config{}).Register(r)

	assetID := uuid.NewString()
	routes := []struct{ method, path string }{
		{http.MethodPost, "/api/storage/upload/initiate"},
		{http.MethodPost, "/api/storage/upload/complete"},
		{http.MethodPut, "/api/storage/upload/stream/" + assetID},
		{http.MethodPost, "/api/storage/bind"},
	}

	denied := []struct {
		name  string
		role  string
		perms []string
	}{
		{"老令牌的 editor（无权限码）", "editor", nil},
		{"只有论坛码的成员", "user", []string{"community.post.create"}},
		{"只有审核权（moderate）", "user", []string{auth.PermissionAssetModerate}},
		{"后台收回上传码、role 仍是 admin", "admin", []string{auth.PermissionAssetModerate}},
	}
	for _, tc := range denied {
		token := signTokenWith(t, key, kid, tc.role, nil, tc.perms)
		for _, rt := range routes {
			w := httptest.NewRecorder()
			req := httptest.NewRequest(rt.method, rt.path, nil)
			req.Header.Set("Authorization", "Bearer "+token)
			r.ServeHTTP(w, req)
			if w.Code != http.StatusForbidden {
				t.Fatalf("%s %s %s 应 403，实际 %d（%s）", tc.name, rt.method, rt.path, w.Code, w.Body.String())
			}
			if !strings.Contains(w.Body.String(), "forbidden") {
				t.Fatalf("%s %s %s 的错误码应是 forbidden，实际 %s", tc.name, rt.method, rt.path, w.Body.String())
			}
		}
	}

	// stream 不在放行清单里：它拿到合法 uuid 会立刻查库，而这里的 store 是空的。
	allowed := []struct {
		name  string
		role  string
		perms []string
	}{
		{"member 组默认持有的上传码", "user", []string{"community.post.create", auth.PermissionAssetUpload}},
		{"* 通配（admin 组）", "admin", []string{"*"}},
	}
	for _, tc := range allowed {
		token := signTokenWith(t, key, kid, tc.role, nil, tc.perms)
		for _, rt := range []struct{ method, path string }{
			{http.MethodPost, "/api/storage/upload/initiate"},
			{http.MethodPost, "/api/storage/upload/complete"},
			{http.MethodPost, "/api/storage/bind"},
		} {
			w := httptest.NewRecorder()
			req := httptest.NewRequest(rt.method, rt.path, nil)
			req.Header.Set("Authorization", "Bearer "+token)
			r.ServeHTTP(w, req)
			if w.Code != 400 {
				t.Fatalf("%s %s %s 应放行到处理器并因空载荷 400，实际 %d（%s）", tc.name, rt.method, rt.path, w.Code, w.Body.String())
			}
		}
	}

	// 解绑不受本码约束（只能删自己的绑定，所有权在处理器内判定）：缺码时仍应走到
	// "非法 id → 404"，而不是被闸门拦成 403。
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/api/storage/bindings/not-a-uuid", nil)
	req.Header.Set("Authorization", "Bearer "+signTokenWith(t, key, kid, "user", nil, []string{"community.post.create"}))
	r.ServeHTTP(w, req)
	if w.Code != 404 {
		t.Fatalf("解绑不应要求上传码：非法 id 应 404，实际 %d（%s）", w.Code, w.Body.String())
	}
}
