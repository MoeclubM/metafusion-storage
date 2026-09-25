package handler

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/MoeclubM/metafusion-storage/internal/store"
)

// ETag 由内容摘要充当版本号：一份资产的字节由它的 sha256 唯一确定（assets_sha256 上有唯一索引），
// 换内容等于换资产，所以这里不存在"标签什么时候该变"的分支，也不需要额外的版本列。
func TestAssetETagIsStableQuotedTag(t *testing.T) {
	sum := strings.Repeat("ab", 32)
	a := store.Asset{ID: "id-1", SHA256: sum}
	want := `"` + sum + `"`
	if got := assetETag(a); got != want {
		t.Fatalf("assetETag = %q，期望 %q", got, want)
	}
	// 两次取值必须一致，否则每次条件请求都命不中，304 形同虚设。
	if assetETag(a) != assetETag(store.Asset{ID: "另一份 id", SHA256: "  " + sum + "  "}) {
		t.Fatal("同一份内容（声明值带空白）的标签不稳定")
	}
	// 摘要被外部改坏成空时退化到资产 id：ETag: "" 不是合法的 entity-tag 语法。
	if got := assetETag(store.Asset{ID: "id-2"}); got != `"id-2"` {
		t.Fatalf("空摘要应退化到 id，实际 %q", got)
	}
}

// If-None-Match 的值由客户端决定：单值、带空白、弱标签、多值列表、* 都是会发出来的形状。
// 认错的两个方向要分开看：认不出（该 304 却回 200）只是白传一次；反过来把不匹配判成 304，
// 用户就会拿一份别的内容的缓存副本当作这一份——那是数据错乱，不是缓存未命中。
func TestETagMatches(t *testing.T) {
	sum := strings.Repeat("cd", 32)
	etag := `"` + sum + `"`
	other := `"` + strings.Repeat("ef", 32) + `"`
	cases := []struct {
		header string
		want   bool
		why    string
	}{
		{"", false, "没带条件头就是普通请求"},
		{etag, true, "同值命中"},
		{"  " + etag + "  ", true, "两侧空白"},
		{"W/" + etag, true, "弱标签只在比较时去掉 W/ 前缀"},
		{"w/" + etag, true, "前缀大小写都容忍"},
		{"*", true, "* 匹配任何当前表示"},
		{other + ", " + etag, true, "多值列表里有一项命中"},
		{etag + ", " + other, true, "命中项在首位"},
		{other, false, "另一份内容的标签不得命中"},
		{`"` + strings.Repeat("CD", 32) + `"`, false, "entity-tag 是不透明串，比对区分大小写"},
		{strings.Trim(etag, `"`), true, "裸值（无引号）也按同值处理：命中的仍是同一份内容，宽松只影响一次回源"},
		{"W/", false, "只剩前缀的空标签不能与任何值相等"},
	}
	for _, tc := range cases {
		if got := etagMatches(tc.header, etag); got != tc.want {
			t.Fatalf("etagMatches(%q, %q) = %v，期望 %v（%s）", tc.header, etag, got, tc.want, tc.why)
		}
	}
}

// 缓存与条件请求这组头本身的形状（不连库）：写了哪几个、没写哪几个。
func TestContentCacheHeadersShape(t *testing.T) {
	gin.SetMode(gin.TestMode)
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/storage/assets/id-1/content", nil)
	asset := store.Asset{ID: "id-1", SHA256: strings.Repeat("ab", 32)}

	etag := contentCacheHeaders(c, asset)
	if etag != assetETag(asset) || !etagMatches(etag, etag) {
		t.Fatalf("返回的标签应当就是写出去的标签，且能命中自己的条件判定：got=%q etag=%q", etag, assetETag(asset))
	}
	// 304 上必须能读到这两个头，缓存副本才留得住再验证依据（RFC 9110 §9.4.1）。
	if got := rec.Header().Get("ETag"); got != etag {
		t.Fatalf("ETag = %q，期望回显 %q", got, etag)
	}
	if got := rec.Header().Get("Cache-Control"); got != "private, max-age="+strconv.Itoa(contentCacheSeconds) {
		t.Fatalf("Cache-Control = %q，期望只进私有缓存 + 短 max-age（可见性按请求判定，共享缓存会把结论烤死）", got)
	}
	// 描述"这一份正文长什么样"的头由分发分支负责，条件请求路径上一律不写。
	if got := rec.Header().Get("Content-Type"); got != "" {
		t.Fatalf("contentCacheHeaders 不该写 Content-Type，实际 %q", got)
	}
	if got := rec.Header().Get("Content-Disposition"); got != "" {
		t.Fatalf("contentCacheHeaders 不该写 Content-Disposition，实际 %q", got)
	}
}

// 命中条件请求时"只回头、不发体"的形状（不连库）：固定的是 gin 与 ResponseRecorder 这一层的
// 真实行为，带库的端到端用例（asset_content_cover_test.go）里那些 304 断言正依赖它。
// 若哪天改成提前写正文、或换成会带 Content-Type 的渲染方式，这里先失败，
// 不必等到只在连着测试库时才跑得到的用例才暴露。
func TestConditionalHitWritesOnlyHeaders(t *testing.T) {
	gin.SetMode(gin.TestMode)
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/storage/assets/id-1/content", nil)
	asset := store.Asset{ID: "id-1", SHA256: strings.Repeat("ab", 32)}

	etag := contentCacheHeaders(c, asset)
	// 没带条件头就不是命中请求：这是浏览器第一次加载那张封面的形状。
	if etagMatches(c.Request.Header.Get("If-None-Match"), etag) {
		t.Fatal("不带 If-None-Match 的请求不该被判成命中")
	}
	// 带上刚发出去的标签（第二次加载，缓存里有一份副本）即命中：走只回头不发体的分支。
	c.Request.Header.Set("If-None-Match", etag)
	if !etagMatches(c.Request.Header.Get("If-None-Match"), etag) {
		t.Fatal("同一份内容的标签应当命中自己的条件判定")
	}
	c.Status(http.StatusNotModified)
	c.Writer.WriteHeaderNow()

	if rec.Code != http.StatusNotModified {
		t.Fatalf("状态码 = %d，期望 304", rec.Code)
	}
	if rec.Body.Len() != 0 {
		t.Fatalf("304 不得带正文，实际 %d 字节", rec.Body.Len())
	}
	if got := rec.Header().Get("ETag"); got != etag {
		t.Fatalf("304 的 ETag = %q，期望回显 %q", got, etag)
	}
	for _, name := range []string{"Content-Type", "Content-Length", "Content-Disposition"} {
		if got := rec.Header().Get(name); got != "" {
			t.Errorf("304 不应带 %s，实际 %q", name, got)
		}
	}
}
