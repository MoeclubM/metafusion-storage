package handler

import (
	"net/http"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/MoeclubM/metafusion-storage/internal/auth"
	"github.com/MoeclubM/metafusion-storage/internal/catalog"
	"github.com/MoeclubM/metafusion-storage/internal/config"
	"github.com/MoeclubM/metafusion-storage/internal/objects"
	"github.com/MoeclubM/metafusion-storage/internal/store"
)

// actionCodePattern 是契约 §2 的动作码形状：<域>.<过去式动作>，全小写 + 下划线。
var actionCodePattern = regexp.MustCompile("^[a-z][a-z0-9_]*\\.[a-z][a-z0-9_]*$")

// TestWriteRoutesAreAudited 是写路由覆盖守卫（契约 §6.3）：遍历 gin 路由树里的
// POST/PUT/PATCH/DELETE 路由，每条要么在动作码注册表里，要么在豁免表里且带一句理由。
// 新增写端点忘了登记动作码 → 这里失败，而不是上线后才发现某类操作零留痕。
func TestWriteRoutesAreAudited(t *testing.T) {
	keys := registeredRouteKeys(t)
	if missing := unauditedWriteRoutes(keys, auditActions, auditExempt); len(missing) != 0 {
		t.Fatalf("以下写路由既没登记动作码、也没带理由豁免：\n%s", strings.Join(missing, "\n"))
	}
	// 冻结路由表里的写路由同样必须被覆盖：契约测试与覆盖守卫一起改，才是"有意新增端点"。
	if missing := unauditedWriteRoutes(frozenRoutes, auditActions, auditExempt); len(missing) != 0 {
		t.Fatalf("frozenRoutes 里的写路由未纳入审计：\n%s", strings.Join(missing, "\n"))
	}
	// 豁免必须带理由，且必须是写路由（把 GET 写进豁免表说明机制被理解错了）。
	for route, why := range auditExempt {
		if strings.TrimSpace(why) == "" {
			t.Fatalf("豁免路由 %s 必须写明理由", route)
		}
		if !isWriteRoute(route) {
			t.Fatalf("豁免表里的 %s 不是写路由：GET 不参与审计，不需要豁免", route)
		}
	}
	// 注册表里不能有孤儿条目，动作码形状也要合规。
	existing := map[string]bool{}
	for _, k := range keys {
		existing[k] = true
	}
	for route, action := range auditActions {
		if !existing[route] {
			t.Fatalf("注册表里的 %s 不是当前路由（动作码 %s 永远不会被写）", route, action)
		}
		if !actionCodePattern.MatchString(action) {
			t.Fatalf("动作码 %q 不符合契约 §2 的 <域>.<过去式动作> 形状", action)
		}
	}
	// 注册表与豁免表不能针对同一条路由各说一套。
	for route := range auditActions {
		if why, ok := auditExempt[route]; ok {
			t.Fatalf("路由 %s 既登记了动作码又声明豁免（%s），二者只能有一个", route, why)
		}
	}
}

// TestUnauditedWriteRoutesJudgement 用合成输入固定判定体本身：
// 漏登记的写路由要被点出、带理由的豁免放行、理由为空视为漏登记、GET 永远不参与。
func TestUnauditedWriteRoutesJudgement(t *testing.T) {
	keys := []string{
		"POST /api/storage/bind",
		"GET /api/storage/stats",
		"DELETE /api/storage/bindings/:id",
		"POST /api/storage/sneaky",
		"PATCH /api/storage/half-exempt",
		"POST /api/storage/empty-reason",
	}
	actions := map[string]string{
		"POST /api/storage/bind":           "binding.created",
		"DELETE /api/storage/bindings/:id": "binding.removed",
	}
	exempt := map[string]string{
		"POST /api/storage/verify-hash":  "读语义",
		"PATCH /api/storage/half-exempt": "有理由就放行",
		"POST /api/storage/empty-reason": "   ",
	}
	got := unauditedWriteRoutes(keys, actions, exempt)
	want := []string{"POST /api/storage/empty-reason", "POST /api/storage/sneaky"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("判定体结果不符：got %v, want %v", got, want)
	}
}

// registeredRouteKeys 取路由树里的「方法 + 路由模板」，与中间件读的 c.FullPath() 同形。
func registeredRouteKeys(t *testing.T) []string {
	t.Helper()
	gin.SetMode(gin.TestMode)
	verifier, err := auth.New(config.Config{JWTIssuer: "https://findverse.cc/api", JWTAudience: "metafusion"})
	if err != nil {
		t.Fatalf("verifier: %v", err)
	}
	r := gin.New()
	New(&store.Store{}, &objects.Store{}, catalog.New(""), verifier, config.Config{}).Register(r)
	keys := []string{}
	for _, route := range r.Routes() {
		keys = append(keys, route.Method+" "+route.Path)
	}
	return keys
}

// unauditedWriteRoutes 是覆盖守卫的判定体（纯函数，便于用合成输入自测）。
// 返回值已排序，便于稳定断言与可读的失败信息。
func unauditedWriteRoutes(keys []string, actions, exempt map[string]string) []string {
	out := []string{}
	for _, key := range keys {
		if !isWriteRoute(key) {
			continue
		}
		if actions[key] != "" {
			continue
		}
		if why, ok := exempt[key]; ok && strings.TrimSpace(why) != "" {
			continue
		}
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}

// isWriteRoute 判定「方法 + 路由」是不是写方法（GET/HEAD/OPTIONS 不参与审计，契约 §7）。
func isWriteRoute(key string) bool {
	method, _, ok := strings.Cut(key, " ")
	if !ok {
		return false
	}
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	}
	return false
}
