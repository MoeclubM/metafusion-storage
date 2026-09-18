package auth

// PAT 下游接入的回归（存储服务）：本地形态预检、60 秒缓存与单飞、上限逐出、
// 401/503 的分工，以及"PAT 身份与 JWT 同形、绝不按角色兜底"这条判定口径。
// 账号服务用同形的桩代替：内省端点不在本仓，桩把跨服务契约面钉住。

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// patToken 造一个形态合法的 PAT 明文：mfp_ + 43 位 base62（= 账号服务侧的最终形状）。
func patToken(fill byte) string {
	return PATPrefix + strings.Repeat(string(fill), patBodyLen)
}

// fakeAuthDoc 与账号服务内省响应同形。
type fakeAuthDoc struct {
	Valid       bool     `json:"valid"`
	UserID      string   `json:"user_id"`
	Username    string   `json:"username"`
	Role        string   `json:"role"`
	Permissions []string `json:"permissions"`
	ExpiresAt   string   `json:"expires_at,omitempty"`
}

// fakeAuth 是内省端点桩：按明文查表判定，并统计被调用次数（缓存/单飞的断言全靠它）。
type fakeAuth struct {
	mu      sync.Mutex
	calls   int
	byToken map[string]fakeAuthDoc
	// status 非 0 时一律回该状态码（模拟账号服务异常），delay 用于放大并发窗口。
	status int
	delay  time.Duration
}

func newFakeAuth(t *testing.T, tokens map[string]fakeAuthDoc) (*fakeAuth, *httptest.Server) {
	t.Helper()
	f := &fakeAuth{byToken: tokens}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != patIntrospectPath || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		f.mu.Lock()
		f.calls++
		status, delay := f.status, f.delay
		f.mu.Unlock()
		if delay > 0 {
			time.Sleep(delay)
		}
		if status != 0 {
			w.WriteHeader(status)
			return
		}
		var in struct {
			Token string `json:"token"`
		}
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		f.mu.Lock()
		doc, ok := f.byToken[in.Token]
		f.mu.Unlock()
		if !ok {
			doc = fakeAuthDoc{Valid: false}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(doc)
	}))
	t.Cleanup(srv.Close)
	return f, srv
}

func (f *fakeAuth) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func (f *fakeAuth) setStatus(status int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.status = status
}

// 明显非法的形态（长度/字符集不对）必须在本地拒绝：不然任何伪造前缀的字符串都是一次免费的内省调用。
func TestPATMalformedRejectedLocally(t *testing.T) {
	f, srv := newFakeAuth(t, nil)
	p := NewPATIntrospector(srv.URL)
	for _, bad := range []string{
		PATPrefix,
		PATPrefix + "too-short",
		PATPrefix + strings.Repeat("a", patBodyLen-1),
		PATPrefix + strings.Repeat("a", patBodyLen+1),
		PATPrefix + strings.Repeat("a", 31),
		PATPrefix + strings.Repeat("a", 65),
		PATPrefix + strings.Repeat("a", patBodyLen-1) + "-",
		PATPrefix + strings.Repeat("a", patBodyLen-1) + "_",
		PATPrefix + strings.Repeat("a", patBodyLen-1) + "中",
		"mfq_" + strings.Repeat("a", patBodyLen),
	} {
		ident, err := p.Introspect(context.Background(), bad)
		if err != nil || ident != nil {
			t.Errorf("%q 应被本地判为无效（ident=%v err=%v）", bad, ident, err)
		}
	}
	if n := f.callCount(); n != 0 {
		t.Fatalf("形态非法不该打账号服务，实际调用 %d 次", n)
	}
}

// 内省结果的三种结论：有效 / 账号服务判否（401、403、200+valid=false）/ 判不了（503、404、429、不可达）。
func TestPATIntrospectOutcomes(t *testing.T) {
	valid := patToken('a')
	unknown := patToken('b')
	refused := patToken('c')
	degraded := patToken('d')
	gone := patToken('e')
	throttled := patToken('h')
	down := patToken('f')
	f, srv := newFakeAuth(t, map[string]fakeAuthDoc{
		valid: {Valid: true, UserID: "u-pat", Username: "kana", Role: "editor",
			Permissions: []string{"community.post.create"}, ExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339)},
	})
	p := NewPATIntrospector(srv.URL)
	ctx := context.Background()

	ident, err := p.Introspect(ctx, valid)
	if err != nil || ident == nil {
		t.Fatalf("有效 PAT 应返回身份: ident=%v err=%v", ident, err)
	}
	if ident.UserID != "u-pat" || ident.Role != "editor" || len(ident.Permissions) != 1 || ident.ExpiresAt.IsZero() {
		t.Fatalf("身份字段不符: %+v", ident)
	}

	// valid=false：账号服务判否（调用方回 401），不是错误。
	if ident, err = p.Introspect(ctx, unknown); ident != nil || err != nil {
		t.Fatalf("valid=false 应按不认该令牌处理: ident=%v err=%v", ident, err)
	}
	// 账号服务直接回 401/403（无效/吊销/过期/封禁都走这里）：同样是确定结论。
	f.setStatus(http.StatusUnauthorized)
	if ident, err = p.Introspect(ctx, refused); ident != nil || err != nil {
		t.Fatalf("内省 401 应按不认该令牌处理: ident=%v err=%v", ident, err)
	}
	// 503 是账号服务"读不动库"的专用码：按依赖不可用回 503，绝不当成令牌无效。
	f.setStatus(http.StatusServiceUnavailable)
	if _, err = p.Introspect(ctx, degraded); err == nil {
		t.Fatal("内省 503 必须返回错误（调用方按 503 处理）")
	}
	// 404（端点还没上线/部署顺序不对）与 429（内省限流）同样不是"令牌无效"的证据：
	// 回 401 会让调用方把有效令牌当废令牌丢掉。
	for status, token := range map[int]string{http.StatusNotFound: gone, http.StatusTooManyRequests: throttled} {
		f.setStatus(status)
		if _, err = p.Introspect(ctx, token); err == nil {
			t.Fatalf("内省 %d 必须按依赖不可用返回错误", status)
		}
	}
	f.setStatus(0)
	srv.Close()
	if _, err = p.Introspect(context.Background(), down); err == nil {
		t.Fatal("账号服务不可达必须返回错误（调用方按 503 处理）")
	}
	// 未配置 AUTH_URL：内省器存在但一律不可用。
	if _, err = NewPATIntrospector("").Introspect(context.Background(), patToken('g')); err == nil {
		t.Fatal("未配置 AUTH_URL 必须按不可用返回错误")
	}
}

// 缓存时长就是**吊销窗口**：60 秒内重复使用同一个 PAT 只打一次账号服务。
func TestPATCacheHonoursTTL(t *testing.T) {
	token := patToken('a')
	f, srv := newFakeAuth(t, map[string]fakeAuthDoc{token: {Valid: true, UserID: "u-1"}})
	now := time.Now()
	p := newPATIntrospector(srv.URL, func() time.Time { return now })
	ctx := context.Background()

	for i := 0; i < 10; i++ {
		if _, err := p.Introspect(ctx, token); err != nil {
			t.Fatalf("第 %d 次内省失败: %v", i+1, err)
		}
	}
	if n := f.callCount(); n != 1 {
		t.Fatalf("60 秒内应只打一次账号服务，实际 %d 次", n)
	}
	if hits, misses, _, size := p.cache.stats(); hits == 0 || misses != 1 || size != 1 {
		t.Fatalf("缓存计数不符: hits=%d misses=%d size=%d", hits, misses, size)
	}

	now = now.Add(PATCacheTTL - time.Second)
	if _, err := p.Introspect(ctx, token); err != nil || f.callCount() != 1 {
		t.Fatalf("未过期不该重新内省: err=%v calls=%d", err, f.callCount())
	}
	// 过期后必须重新问：这就是"吊销最长 60 秒生效"的实现。
	now = now.Add(2 * time.Second)
	if _, err := p.Introspect(ctx, token); err != nil || f.callCount() != 2 {
		t.Fatalf("过期后必须重新内省: err=%v calls=%d", err, f.callCount())
	}
}

// 令牌自身过期比缓存窗口更早时，缓存不得把有效期往后拖。
func TestPATCacheDoesNotOutliveTokenExpiry(t *testing.T) {
	token := patToken('a')
	now := time.Now()
	f, srv := newFakeAuth(t, map[string]fakeAuthDoc{token: {
		Valid: true, UserID: "u-1",
		ExpiresAt: now.Add(10 * time.Second).UTC().Format(time.RFC3339),
	}})
	p := newPATIntrospector(srv.URL, func() time.Time { return now })
	if _, err := p.Introspect(context.Background(), token); err != nil {
		t.Fatal(err)
	}
	now = now.Add(11 * time.Second)
	if _, err := p.Introspect(context.Background(), token); err != nil {
		t.Fatal(err)
	}
	if n := f.callCount(); n != 2 {
		t.Fatalf("令牌过期后必须重新内省（缓存不得越过 expires_at），实际 %d 次", n)
	}
}

// 并发同键只打一次：没有单飞，一批并发请求会把账号服务打爆（每个都是缓存未命中）。
func TestPATCacheSingleflight(t *testing.T) {
	token := patToken('a')
	f, srv := newFakeAuth(t, map[string]fakeAuthDoc{token: {Valid: true, UserID: "u-1"}})
	f.delay = 50 * time.Millisecond
	p := NewPATIntrospector(srv.URL)

	var wg sync.WaitGroup
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if ident, err := p.Introspect(context.Background(), token); err != nil || ident == nil {
				t.Errorf("并发内省失败: ident=%v err=%v", ident, err)
			}
		}()
	}
	wg.Wait()
	if n := f.callCount(); n != 1 {
		t.Fatalf("并发同键应只打一次账号服务，实际 %d 次", n)
	}
}

// 缓存必须有上限与逐出：任何人都能构造 mfp_ 前缀的字符串来喂缓存。
func TestPATCacheIsBounded(t *testing.T) {
	c := newPATCache(time.Now)
	if PATCacheMax < 16 {
		t.Fatalf("上限太小，用例失去意义: %d", PATCacheMax)
	}
	for i := 0; i < PATCacheMax*2; i++ {
		c.storeLocked(patHash(patToken('a')+strconv.Itoa(i)), patCacheEntry{cachedUntil: time.Now().Add(time.Hour)})
	}
	_, _, evictions, size := c.stats()
	if size > PATCacheMax {
		t.Fatalf("缓存条目 %d 超过上限 %d", size, PATCacheMax)
	}
	if evictions == 0 {
		t.Fatal("超过上限必须逐出，实际 evictions=0")
	}
}

// 满了要逐出时先清过期项（它们只是白占内存），不是无脑扔掉最老的活条目。
func TestPATCacheEvictsExpiredFirst(t *testing.T) {
	now := time.Now()
	c := newPATCache(func() time.Time { return now })
	for i := 0; i < PATCacheMax; i++ {
		c.storeLocked(patHash("stale-"+strconv.Itoa(i)), patCacheEntry{cachedUntil: now.Add(-time.Minute)})
	}
	c.storeLocked(patHash("fresh"), patCacheEntry{cachedUntil: now.Add(time.Hour)})
	if _, _, _, size := c.stats(); size != 1 {
		t.Fatalf("满仓时过期项应被全部清掉，剩余 %d 条", size)
	}
}

// 手工构造的空权限 PAT（role 仍是 admin）必须一无所获：这是"永不按角色兜底"的直接证明，
// 即便创建端点已经禁止空 scopes，也要防将来回退。
func TestPATPrincipalNeverFallsBackToRole(t *testing.T) {
	pat := &Principal{ID: "u-1", Role: "admin", FromPAT: true}
	for _, code := range []string{permissionWildcard, PermissionAssetUpload, PermissionAssetModerate} {
		if pat.Can(code) {
			t.Fatalf("空权限的 PAT 不该持有 %s", code)
		}
		if pat.HasPermission(code) {
			t.Fatalf("HasPermission 对空权限的 PAT 不该放行 %s", code)
		}
	}
	// 对照：同角色的**老令牌**（没有 permissions 声明、不是 PAT）仍按历史角色兜底——
	// 这条差异是有意的，不能顺手把老令牌也收紧。
	legacy := &Principal{ID: "u-2", Role: "admin"}
	if !legacy.Can(PermissionAssetModerate) {
		t.Fatal("老令牌的 admin 角色兜底必须保持")
	}
	if legacy.HasPermission(PermissionAssetModerate) {
		t.Fatal("HasPermission 不对任何角色兜底：老令牌也不该在空 permissions 上放行")
	}
	// 权限码非空时两者必须完全等价（Can 只是多了老令牌兜底那一段）。
	for _, p := range []*Principal{
		{ID: "u-3", Role: "user", Permissions: []string{PermissionAssetUpload}},
		{ID: "u-4", Role: "user", Permissions: []string{permissionWildcard}},
		{ID: "u-5", Role: "admin", Permissions: []string{PermissionAssetUpload}, FromPAT: true},
	} {
		for _, code := range []string{PermissionAssetUpload, PermissionAssetModerate} {
			if p.Can(code) != p.HasPermission(code) {
				t.Fatalf("permissions 非空时 Can 与 HasPermission 必须等价：%+v / %s", p, code)
			}
		}
	}
}
