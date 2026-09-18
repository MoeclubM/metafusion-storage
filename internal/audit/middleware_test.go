package audit

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

const (
	testUserID  = "11111111-1111-1111-1111-111111111111"
	testBindID  = "22222222-2222-2222-2222-222222222222"
	testAssetID = "33333333-3333-3333-3333-333333333333"
)

// newMiddlewareRouter 挂一个最小路由面：两条登记写路由 + 一条豁免写路由 + 一条未登记写路由 + 一条 GET。
// 中间件挂在组上（与真实服务一致），处理器用 Describe/Fail 复现真实调用形状。
func newMiddlewareRouter(t *testing.T, rec *Recorder) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	actions := map[string]string{
		"POST /api/storage/bind":                  "binding.created",
		"PUT /api/storage/upload/stream/:assetId": "asset.upload_streamed",
	}
	exempt := map[string]string{"POST /api/storage/verify-hash": "读语义：探测与回读校验，不改资产状态"}
	r := gin.New()
	api := r.Group("/api/storage")
	api.Use(Middleware(Options{
		Recorder: rec,
		Actions:  actions,
		Exempt:   exempt,
		Actor: func(c *gin.Context) Actor {
			if c.GetHeader("X-Test-Anon") != "" {
				return Actor{CredentialType: CredentialAnonymous}
			}
			return Actor{UserID: testUserID, Username: "kana", CredentialType: CredentialPAT}
		},
	}))
	api.POST("/bind", func(c *gin.Context) {
		switch c.GetHeader("X-Test-Outcome") {
		case "fail":
			// 真实处理器就是"记错误码 + 写响应体"这一个动作（见 handler.fail）。
			Fail(c, "invalid_payload")
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_payload"})
		case "no-code":
			c.JSON(http.StatusInternalServerError, gin.H{"error": "module_error"})
		default:
			Describe(c, Detail{TargetType: "binding", TargetID: testBindID, Changes: map[string]any{"asset_id": testAssetID}})
			c.JSON(http.StatusOK, gin.H{"ok": true})
		}
	})
	api.PUT("/upload/stream/:assetId", func(c *gin.Context) {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "module_error"})
	})
	api.POST("/verify-hash", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"exists": false}) })
	api.POST("/unregistered", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })
	api.GET("/stats", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"assets": 0}) })
	return r
}

// call 发一次请求；requestID 为空表示不带 X-Request-Id（中间件应生成并回写）。
func call(r *gin.Engine, method, path, requestID, outcome, ua string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	if requestID != "" {
		req.Header.Set("X-Request-Id", requestID)
	}
	if outcome != "" {
		req.Header.Set("X-Test-Outcome", outcome)
	}
	if ua != "" {
		req.Header.Set("User-Agent", ua)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

// entryByRequestID 取某次请求对应的审计行（应恰好一条）。
func entryByRequestID(t *testing.T, entries []Entry, requestID string) Entry {
	t.Helper()
	found := []Entry{}
	for _, e := range entries {
		if e.RequestID == requestID {
			found = append(found, e)
		}
	}
	if len(found) != 1 {
		t.Fatalf("request_id=%s 应恰好一条审计行，实际 %d 条", requestID, len(found))
	}
	return found[0]
}

// TestMiddlewareAuditsRegisteredWritesOnly：登记路由写审计、未登记/GET/豁免路由不写；
// 成功与失败两种结果的 result / error_code / http_status 判定都固定住。
func TestMiddlewareAuditsRegisteredWritesOnly(t *testing.T) {
	cap := &capture{}
	rec := newTestRecorder(ServiceName, 64, cap.write, nil)
	r := newMiddlewareRouter(t, rec)

	if w := call(r, http.MethodPost, "/api/storage/bind", "rid-ok", "", ""); w.Code != http.StatusOK {
		t.Fatalf("bind 应 200，实际 %d", w.Code)
	}
	if w := call(r, http.MethodPost, "/api/storage/bind", "rid-fail", "fail", ""); w.Code != http.StatusBadRequest {
		t.Fatalf("bind(fail) 应 400，实际 %d", w.Code)
	}
	if w := call(r, http.MethodPost, "/api/storage/bind", "rid-nocode", "no-code", ""); w.Code != http.StatusInternalServerError {
		t.Fatalf("bind(no-code) 应 500，实际 %d", w.Code)
	}
	if w := call(r, http.MethodPut, "/api/storage/upload/stream/"+testAssetID, "rid-stream", "", ""); w.Code != http.StatusInternalServerError {
		t.Fatalf("stream 应 500，实际 %d", w.Code)
	}
	// 以下三条都不该产生审计行。
	call(r, http.MethodPost, "/api/storage/verify-hash", "rid-exempt", "", "")
	call(r, http.MethodPost, "/api/storage/unregistered", "rid-unreg", "", "")
	call(r, http.MethodGet, "/api/storage/stats", "rid-get", "", "")

	rec.Close()
	entries := cap.all()
	if len(entries) != 4 {
		t.Fatalf("应恰好 4 条审计行（3 条 bind + 1 条 stream），实际 %d：%+v", len(entries), entries)
	}

	ok := entryByRequestID(t, entries, "rid-ok")
	if ok.Action != "binding.created" || ok.Service != ServiceName {
		t.Fatalf("动作码/service 不符: %+v", ok)
	}
	if ok.Result != "success" || ok.ErrorCode != "" || ok.HTTPStatus != http.StatusOK {
		t.Fatalf("成功行应为 result=success/error_code 空/200: %+v", ok)
	}
	if ok.ActorUserID != testUserID || ok.ActorUsername != "kana" || ok.CredentialType != CredentialPAT {
		t.Fatalf("操作者字段不符: %+v", ok)
	}
	if ok.RequestMethod != http.MethodPost || ok.Route != "/api/storage/bind" {
		t.Fatalf("方法/路由模板不符: %+v", ok)
	}
	if ok.TargetType != "binding" || ok.TargetID != testBindID || ok.Changes["asset_id"] != testAssetID {
		t.Fatalf("被动对象/变更摘要不符: %+v", ok)
	}
	if ok.ActorIP == "" {
		t.Fatal("actor_ip 不该为空（gin ClientIP）")
	}
	if _, err := uuid.Parse(ok.ID); err != nil {
		t.Fatalf("审计行 id 应是 uuid: %q", ok.ID)
	}

	failed := entryByRequestID(t, entries, "rid-fail")
	if failed.Result != "failure" || failed.ErrorCode != "invalid_payload" || failed.HTTPStatus != http.StatusBadRequest {
		t.Fatalf("失败行应带处理器给的错误码: %+v", failed)
	}

	noCode := entryByRequestID(t, entries, "rid-nocode")
	if noCode.Result != "failure" || noCode.ErrorCode != "http_500" {
		t.Fatalf("没记错误码时应回落 http_<status>: %+v", noCode)
	}

	stream := entryByRequestID(t, entries, "rid-stream")
	if stream.Action != "asset.upload_streamed" || stream.Route != "/api/storage/upload/stream/:assetId" {
		t.Fatalf("route 应存模板而不是原始路径: %+v", stream)
	}
	if stream.Result != "failure" || stream.ErrorCode != "http_500" {
		t.Fatalf("流式上传失败行不符: %+v", stream)
	}
}

// TestMiddlewareRequestID：请求头透传 + 缺省生成并回写响应头（网关与应用日志靠它关联）。
func TestMiddlewareRequestID(t *testing.T) {
	cap := &capture{}
	rec := newTestRecorder(ServiceName, 16, cap.write, nil)
	r := newMiddlewareRouter(t, rec)

	w := call(r, http.MethodPost, "/api/storage/bind", "rid-passthrough", "", "")
	if got := w.Header().Get("X-Request-Id"); got != "rid-passthrough" {
		t.Fatalf("响应头应回写调用方给的 id，实际 %q", got)
	}
	w = call(r, http.MethodPost, "/api/storage/bind", "", "", "")
	generated := w.Header().Get("X-Request-Id")
	if _, err := uuid.Parse(generated); err != nil {
		t.Fatalf("缺省应生成 uuid 并回写响应头，实际 %q", generated)
	}
	// 未审计的 GET 也回写：id 是"这次请求"的关联键，与是否写审计无关。
	w = call(r, http.MethodGet, "/api/storage/stats", "", "", "")
	if w.Header().Get("X-Request-Id") == "" {
		t.Fatal("GET 也应回写 X-Request-Id")
	}

	rec.Close()
	entries := cap.all()
	if _, ok := findEntry(entries, "rid-passthrough"); !ok {
		t.Fatal("透传的 request_id 应落进审计行")
	}
	if _, ok := findEntry(entries, generated); !ok {
		t.Fatal("生成的 request_id 应落进审计行")
	}
}

func findEntry(entries []Entry, requestID string) (Entry, bool) {
	for _, e := range entries {
		if e.RequestID == requestID {
			return e, true
		}
	}
	return Entry{}, false
}

// TestMiddlewareAnonymousActor：没有身份时按 anonymous 记，不能拿上一个请求的身份凑数。
func TestMiddlewareAnonymousActor(t *testing.T) {
	cap := &capture{}
	rec := newTestRecorder(ServiceName, 16, cap.write, nil)
	r := newMiddlewareRouter(t, rec)
	req := httptest.NewRequest(http.MethodPost, "/api/storage/bind", nil)
	req.Header.Set("X-Request-Id", "rid-anon")
	req.Header.Set("X-Test-Anon", "1")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	rec.Close()
	entries := cap.all()
	e := entryByRequestID(t, entries, "rid-anon")
	if e.CredentialType != CredentialAnonymous || e.ActorUserID != "" || e.ActorUsername != "" {
		t.Fatalf("匿名请求的身份字段不符: %+v", e)
	}
}

// TestMiddlewareTruncatesUserAgent：UA 截断到 512 字符后落库。
func TestMiddlewareTruncatesUserAgent(t *testing.T) {
	cap := &capture{}
	rec := newTestRecorder(ServiceName, 16, cap.write, nil)
	r := newMiddlewareRouter(t, rec)
	call(r, http.MethodPost, "/api/storage/bind", "rid-ua", "", strings.Repeat("u", 4096))
	rec.Close()
	e := entryByRequestID(t, cap.all(), "rid-ua")
	if n := len([]rune(e.ActorUserAgent)); n != MaxUserAgentLen {
		t.Fatalf("UA 应截断到 %d 字符，实际 %d", MaxUserAgentLen, n)
	}
}

// TestDescribeMerges：同一请求多次 Describe 合并（后写的同名键覆盖），空 Detail 是 no-op。
func TestDescribeMerges(t *testing.T) {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	Describe(c, Detail{TargetType: "asset", TargetID: testAssetID, Changes: map[string]any{"status": "pending", "sha256": "abc"}})
	Describe(c, Detail{TargetID: "44444444-4444-4444-4444-444444444444", Changes: map[string]any{"status": "complete", "extra": 1}})
	Describe(c, Detail{})
	v, ok := c.Get(detailKey)
	if !ok {
		t.Fatal("Describe 应把草稿写进上下文")
	}
	d, ok := v.(*Detail)
	if !ok {
		t.Fatalf("草稿类型不符: %T", v)
	}
	if d.TargetType != "asset" {
		t.Fatalf("空字段不该覆盖已有 target_type: %+v", d)
	}
	if d.TargetID != "44444444-4444-4444-4444-444444444444" {
		t.Fatalf("非空 target_id 应覆盖: %+v", d)
	}
	if d.Changes["status"] != "complete" || d.Changes["sha256"] != "abc" || d.Changes["extra"] != 1 {
		t.Fatalf("changes 应合并（同名覆盖、其余保留）: %#v", d.Changes)
	}
	// 中间件没挂（没预置草稿）时 Describe 仍可用：它自己建一份。
	c2, _ := gin.CreateTestContext(httptest.NewRecorder())
	Describe(c2, Detail{TargetType: "binding"})
	if _, ok := c2.Get(detailKey); !ok {
		t.Fatal("无中间件时 Describe 也应留下草稿")
	}
	// nil 上下文不 panic（防御性契约）。
	Describe(nil, Detail{TargetType: "asset"})
	Fail(nil, "invalid_payload")
}
