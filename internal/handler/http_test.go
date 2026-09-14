package handler

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/MoeclubM/metafusion-storage/internal/auth"
	"github.com/MoeclubM/metafusion-storage/internal/catalog"
	"github.com/MoeclubM/metafusion-storage/internal/config"
	"github.com/MoeclubM/metafusion-storage/internal/objects"
	"github.com/MoeclubM/metafusion-storage/internal/store"
)

const (
	testIssuer   = "https://findverse.cc/api"
	testAudience = "metafusion"
)

func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// 与账号服务同格式的 JWKS：kid 取公钥 SPKI 的 SHA-256 前 8 字节，n/e 用 base64url。
func jwksServer(t *testing.T, key *rsa.PrivateKey) (*httptest.Server, string) {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	sum := sha256.Sum256(der)
	kid := b64url(sum[:8])
	doc := map[string]any{"keys": []map[string]any{{
		"kty": "RSA", "use": "sig", "alg": "RS256", "kid": kid,
		"n": b64url(key.PublicKey.N.Bytes()),
		"e": b64url(big.NewInt(int64(key.PublicKey.E)).Bytes()),
	}}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(doc)
	}))
	t.Cleanup(srv.Close)
	return srv, kid
}

func signToken(t *testing.T, key *rsa.PrivateKey, kid, role string) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub":                "11111111-1111-1111-1111-111111111111",
		"preferred_username": "kana",
		"role":               role,
		"iss":                testIssuer,
		"aud":                testAudience,
		"exp":                time.Now().Add(10 * time.Minute).Unix(),
		"iat":                time.Now().Unix(),
	})
	token.Header["kid"] = kid
	signed, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return signed
}

func newVerifier(t *testing.T, jwksURL string) *auth.Verifier {
	t.Helper()
	v, err := auth.New(config.Config{JWKSURL: jwksURL, JWTIssuer: testIssuer, JWTAudience: testAudience})
	if err != nil {
		t.Fatalf("verifier: %v", err)
	}
	return v
}

// 跨服务验签：账号服务签发的令牌必须能被存储服务用 JWKS 本地验签。
func TestMiddlewareResolvesPrincipalFromJWKS(t *testing.T) {
	gin.SetMode(gin.TestMode)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	srv, kid := jwksServer(t, key)
	verifier := newVerifier(t, srv.URL)

	r := gin.New()
	api := r.Group("/api")
	api.Use(verifier.Middleware())
	api.GET("/probe", func(c *gin.Context) {
		p := auth.Current(c)
		if p == nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "anonymous"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"id": p.ID, "role": p.Role})
	})

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/probe", nil))
	if w.Code != 401 {
		t.Fatalf("匿名应为 401，实际 %d", w.Code)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/probe", nil)
	req.Header.Set("Authorization", "Bearer "+signToken(t, key, kid, "admin"))
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("带令牌应 200，实际 %d（%s）", w.Code, w.Body.String())
	}
	var got map[string]string
	_ = json.Unmarshal(w.Body.Bytes(), &got)
	if got["role"] != "admin" {
		t.Fatalf("身份还原不符: %v", got)
	}
}

// 鉴权边界与实体可见性都在触碰数据库之前判定：匿名写 401；实体不可见一律 404。
func TestAuthBoundaryBeforeDatabase(t *testing.T) {
	gin.SetMode(gin.TestMode)
	verifier := newVerifier(t, "http://127.0.0.1:1/jwks")
	r := gin.New()
	New(&store.Store{}, &objects.Store{}, catalog.New(""), verifier, config.Config{}).Register(r)

	for _, tc := range []struct{ method, path string }{
		{http.MethodPost, "/api/storage/upload/initiate"},
		{http.MethodPost, "/api/storage/upload/complete"},
		{http.MethodPost, "/api/storage/bind"},
		{http.MethodGet, "/api/storage/stats"},
		{http.MethodPut, "/api/storage/upload/stream/" + uuid.NewString()},
		{http.MethodDelete, "/api/storage/bindings/" + uuid.NewString()},
	} {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(tc.method, tc.path, nil))
		if w.Code != 401 {
			t.Fatalf("%s %s 匿名应 401，实际 %d", tc.method, tc.path, w.Code)
		}
	}

	// verify-hash 故意允许匿名（客户端先探测秒传），但空载荷必须是 400 而不是 500；
	// 是否存在由 h.readable 判定，未登录时一律按"不存在"返回，不泄露他人上传。
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/storage/verify-hash", nil))
	if w.Code != 400 {
		t.Fatalf("verify-hash 空载荷应 400，实际 %d", w.Code)
	}

	// 目录地址为空时实体不可见：文件列表入口必须 404，且不查库、不泄露存在性。
	w = httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/storage/entities/"+uuid.NewString()+"/files", nil))
	if w.Code != 404 {
		t.Fatalf("不可见实体的文件列表应 404，实际 %d", w.Code)
	}
	// 非法 UUID 同样 404（而不是 500）。
	w = httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/storage/entities/not-a-uuid/files", nil))
	if w.Code != 404 {
		t.Fatalf("非法实体 id 应 404，实际 %d", w.Code)
	}
}
