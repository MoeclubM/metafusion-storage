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

// 四个 JSON 写接口此前各自直接 ShouldBindJSON，既没有本服务自己的请求体上限
// （网关的 client_max_body_size 是 1G），也静默忽略拼错的字段。
//
// 每份载荷都只用**声明内**的字段，且刻意选字段值不会被后续校验拦住的那一类：
// 这样"被上限拦住"与"被业务校验拦住"不会撞成同一个响应——上限一旦失效，
// 用例会看到 panic（继续走到数据库）或别的状态码/错误码，而不是 invalid_payload。
func TestJSONWriteEndpointsRejectOversizedBody(t *testing.T) {
	gin.SetMode(gin.TestMode)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	srv, kid := jwksServer(t, key)
	verifier := newVerifier(t, srv.URL)
	r := gin.New()
	New(&store.Store{}, &objects.Store{}, catalog.New(""), verifier, config.Config{}).Register(r)
	token := signTokenWith(t, key, kid, "user", nil, []string{auth.PermissionAssetUpload})

	pad := strings.Repeat("a", 2<<20)
	assetID := uuid.NewString()
	cases := []struct {
		name, path, payload string
	}{
		{"initiate", "/api/storage/upload/initiate", `{"mime_type":"` + pad + `"}`},
		{"complete", "/api/storage/upload/complete", `{"asset_id":"` + assetID + `","upload_id":"` + pad + `"}`},
		{"bind", "/api/storage/bind", `{"asset_id":"` + assetID + `","target_entity_id":"` + assetID + `","binding_role":"` + pad + `"}`},
		{"verify-hash", "/api/storage/verify-hash", `{"asset_id":"` + pad + `"}`},
	}
	for _, tc := range cases {
		req := httptest.NewRequest(http.MethodPost, tc.path, strings.NewReader(tc.payload))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != 400 || !strings.Contains(w.Body.String(), "invalid_payload") {
			t.Fatalf("%s 超限请求体应 400 invalid_payload，实际 %d（%s）", tc.name, w.Code, w.Body.String())
		}
	}
}
