package handler

// PAT 在存储服务的端到端回归：真库 + 真路由 + 同形的账号服务内省桩。
// 覆盖"PAT 可读需登录接口""scopes 收紧时越权写被拒""无效 PAT 401"
// "账号服务不可达 503"与"缓存命中不再打内省"。

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/MoeclubM/metafusion-storage/internal/auth"
	"github.com/MoeclubM/metafusion-storage/internal/catalog"
	"github.com/MoeclubM/metafusion-storage/internal/config"
	"github.com/MoeclubM/metafusion-storage/internal/objects"
	"github.com/MoeclubM/metafusion-storage/internal/store"
	"github.com/MoeclubM/metafusion-storage/internal/testutil"
)

// patBearer 造形态合法的 PAT 明文：mfp_ + 43 位 base62（账号服务侧的最终形状）。
func patBearer(fill byte) string { return auth.PATPrefix + strings.Repeat(string(fill), 43) }

// patAuthStub 是内省端点桩：按明文回固定判定，并统计被调用次数。
type patAuthStub struct {
	mu     sync.Mutex
	calls  int
	bodies map[string]map[string]any
}

func newPATAuthStub(t *testing.T, bodies map[string]map[string]any) (*patAuthStub, *httptest.Server) {
	t.Helper()
	stub := &patAuthStub{bodies: bodies}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/auth/tokens/introspect" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		stub.mu.Lock()
		stub.calls++
		stub.mu.Unlock()
		var in struct {
			Token string `json:"token"`
		}
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		stub.mu.Lock()
		body, ok := stub.bodies[in.Token]
		stub.mu.Unlock()
		if !ok {
			body = map[string]any{"valid": false}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(body)
	}))
	t.Cleanup(srv.Close)
	return stub, srv
}

func (s *patAuthStub) callCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

func TestPATEndToEnd(t *testing.T) {
	gin.SetMode(gin.TestMode)
	moderator := patBearer('m')    // 只有审核码：读全局统计
	uploader := patBearer('u')     // 上传码：过 requireUpload
	outsider := patBearer('o')     // 只有审核码：上传越权（两个码互不蕴含）
	adminNoScope := patBearer('d') // 管理员但 scopes 为空
	fresh := patBearer('f')        // 只在最后一阶段用：届时账号服务已下线

	stub, srv := newPATAuthStub(t, map[string]map[string]any{
		moderator: {"valid": true, "user_id": "bbbbbbbb-0000-0000-0000-000000000001", "username": "pat-moderator",
			"role": "user", "permissions": []string{auth.PermissionAssetModerate}},
		uploader: {"valid": true, "user_id": "bbbbbbbb-0000-0000-0000-000000000002", "username": "pat-uploader",
			"role": "user", "permissions": []string{auth.PermissionAssetUpload}},
		outsider: {"valid": true, "user_id": "bbbbbbbb-0000-0000-0000-000000000003", "username": "pat-outsider",
			"role": "user", "permissions": []string{auth.PermissionAssetModerate}},
		adminNoScope: {"valid": true, "user_id": "bbbbbbbb-0000-0000-0000-000000000004", "username": "pat-admin",
			"role": "admin", "permissions": []string{}},
		fresh: {"valid": true, "user_id": "bbbbbbbb-0000-0000-0000-000000000005", "username": "pat-fresh",
			"role": "user", "permissions": []string{auth.PermissionAssetUpload}},
	})

	ctx := context.Background()
	s, err := store.Open(ctx, testutil.DSN(t))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer s.Close()
	if err = s.Init(ctx); err != nil {
		t.Fatalf("init schema: %v", err)
	}
	cfg := config.Config{
		Root:         t.TempDir(),
		S3Bucket:     "metafusion-test",
		PresignTTL:   5 * time.Minute,
		MaxPartCount: 10000,
	}
	objs, err := objects.New(ctx, cfg)
	if err != nil {
		t.Fatalf("objects.New: %v", err)
	}

	// 验签公钥刻意指向不可达地址：PAT 路径不依赖本地验签材料（JWKS 也不该被访问）。
	verifier := newVerifier(t, "http://127.0.0.1:1/jwks")
	verifier.SetPAT(auth.NewPATIntrospector(srv.URL))
	router := gin.New()
	New(s, objs, catalog.New(""), verifier, cfg).Register(router)

	do := func(method, path, payload, bearer string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(method, path, strings.NewReader(payload))
		req.Header.Set("Content-Type", "application/json")
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w
	}

	// 1) 读接口（需登录 + storage.asset.moderate）：PAT 能读到全局统计，且响应不带 mf_session cookie。
	w := do(http.MethodGet, "/api/storage/stats", "", moderator)
	if w.Code != http.StatusOK {
		t.Fatalf("持审核码的 PAT 读统计应 200，实际 %d：%s", w.Code, w.Body.String())
	}
	if cookie := w.Header().Get("Set-Cookie"); cookie != "" {
		t.Fatalf("PAT 请求不该产出 cookie: %s", cookie)
	}
	// 2) 越权写：上传码与审核码互不蕴含，持审核码的 PAT 不能上传 → 403。
	//    探针载荷刻意非法：400 只可能出现在权限闸门放行之后。
	w = do(http.MethodPost, "/api/storage/upload/initiate", "{}", outsider)
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "forbidden") {
		t.Fatalf("缺 storage.asset.upload 的 PAT 上传应 403，实际 %d：%s", w.Code, w.Body.String())
	}
	// 3) 持码的 PAT 过闸门（载荷不合由处理器回 400，证明身份进了上下文）。
	w = do(http.MethodPost, "/api/storage/upload/initiate", "{}", uploader)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "invalid_payload") {
		t.Fatalf("持码 PAT 应过闸门到处理器，实际 %d：%s", w.Code, w.Body.String())
	}
	// 4) 管理员但 scopes 空：PAT 身份永不回落角色兜底（第二轮防线，创建端点已禁止空 scopes）。
	w = do(http.MethodPost, "/api/storage/upload/initiate", "{}", adminNoScope)
	if w.Code != http.StatusForbidden {
		t.Fatalf("scopes 为空的管理员 PAT 不该按角色兜底放行，实际 %d：%s", w.Code, w.Body.String())
	}
	// 5) 缓存命中：同一令牌的第二次请求不再打内省端点。
	w = do(http.MethodGet, "/api/storage/stats", "", moderator)
	if w.Code != http.StatusOK {
		t.Fatalf("PAT 第二次读应 200，实际 %d：%s", w.Code, w.Body.String())
	}
	if n := stub.callCount(); n != 4 {
		t.Fatalf("四个令牌各内省一次（第二次请求应命中缓存），实际 %d 次", n)
	}
	// 6) 无效 PAT：401 + 稳定机器码（无效/吊销/过期共用一个码）。形态合法，所以会问一次内省。
	w = do(http.MethodGet, "/api/storage/stats", "", patBearer('z'))
	if w.Code != http.StatusUnauthorized || !strings.Contains(w.Body.String(), auth.CodeInvalidToken) {
		t.Fatalf("无效 PAT 应 401 %s，实际 %d：%s", auth.CodeInvalidToken, w.Code, w.Body.String())
	}
	// 6b) 形态明显非法（长度不对）：本地就拒，不打账号服务。
	w = do(http.MethodGet, "/api/storage/stats", "", auth.PATPrefix+"not-a-real-token")
	if w.Code != http.StatusUnauthorized || !strings.Contains(w.Body.String(), auth.CodeInvalidToken) {
		t.Fatalf("形态非法的 PAT 应 401 %s，实际 %d：%s", auth.CodeInvalidToken, w.Code, w.Body.String())
	}
	if n := stub.callCount(); n != 5 {
		t.Fatalf("形态非法的令牌不该打内省端点，实际累计 %d 次", n)
	}
	// 7) 账号服务不可达：503 + 稳定机器码（不是 401——那会让调用方去换凭据而不是重试）。
	//    必须用一个尚未内省过的令牌，否则会命中缓存，测不到依赖故障这条路径。
	srv.Close()
	w = do(http.MethodGet, "/api/storage/stats", "", fresh)
	if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), auth.CodeAuthUnavailable) {
		t.Fatalf("账号服务不可达应 503 %s，实际 %d：%s", auth.CodeAuthUnavailable, w.Code, w.Body.String())
	}
	// 8) 未装配内省器（未配置 AUTH_URL）时同样按依赖不可用处理，而不是"凭据错"。
	bare := newVerifier(t, "http://127.0.0.1:1/jwks")
	bareRouter := gin.New()
	New(s, objs, catalog.New(""), bare, cfg).Register(bareRouter)
	req := httptest.NewRequest(http.MethodGet, "/api/storage/stats", nil)
	req.Header.Set("Authorization", "Bearer "+patBearer('g'))
	w = httptest.NewRecorder()
	bareRouter.ServeHTTP(w, req)
	if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), auth.CodeAuthUnavailable) {
		t.Fatalf("未配置 AUTH_URL 应 503 %s，实际 %d：%s", auth.CodeAuthUnavailable, w.Code, w.Body.String())
	}
	// 累计 5 次 = moderator/uploader/outsider/adminNoScope 各一次 + 形态合法的未知令牌一次；
	// 缓存命中的第二次读、形态非法的明文、账号服务已下线、未配置内省器这四处都不产生调用。
	if n := stub.callCount(); n != 5 {
		t.Fatalf("内省调用次数应停在 5（缓存/本地预检/依赖故障都不该再打），实际累计 %d 次", n)
	}
}
