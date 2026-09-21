package catalog

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// X01 身份契约：identity 端点一次返回存活身份与历史别名（只读投影，不改写引用）。
func TestIdentityReturnsCanonicalAndAliases(t *testing.T) {
	const oldID = "11111111-1111-1111-1111-111111111111"
	const newID = "22222222-2222-2222-2222-222222222222"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/catalog/entities/"+oldID+"/identity" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"canonical_id": newID,
			"aliases":      []string{oldID},
			"entity":       map[string]any{"id": newID, "kind": "work"},
		})
	}))
	defer srv.Close()

	v, err := New(srv.URL).Identity(context.Background(), oldID, "", "")
	if err != nil {
		t.Fatalf("Identity 失败: %v", err)
	}
	if v.CanonicalID != newID || v.Entity.Kind != "work" {
		t.Fatalf("存活身份不符: %+v", v)
	}
	if len(v.Aliases) != 1 || v.Aliases[0] != oldID {
		t.Fatalf("历史别名不符: %+v", v.Aliases)
	}
	if got := AliasSet(v.CanonicalID, append([]string{oldID}, v.Aliases...)...); len(got) != 2 {
		t.Fatalf("聚合集合应含请求 ID 与 canonical（去重）：%v", got)
	}
}

// 旧目录没有 identity 端点：对一切 id 都是 404，此时按旧 /resolve 跟随合并重定向，
// 不能直接报不可见——否则旧目录下所有文件列表都变 404。
func TestIdentityFallsBackToResolveOnLegacyDirectory(t *testing.T) {
	const oldID = "33333333-3333-3333-3333-333333333333"
	const newID = "44444444-4444-4444-4444-444444444444"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/catalog/entities/" + oldID + "/resolve":
			_ = json.NewEncoder(w).Encode(map[string]any{"id": newID, "kind": "track"})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	v, err := New(srv.URL).Identity(context.Background(), oldID, "", "")
	if err != nil {
		t.Fatalf("旧路径 Identity 失败: %v", err)
	}
	if v.CanonicalID != newID || v.Entity.Kind != "track" {
		t.Fatalf("旧路径存活身份不符: %+v", v)
	}
}

// 真正不可见的实体：本体与 /resolve 都 404，返回 ErrNotVisible（调用方 404，
// 不是 503，更不是空列表）。
func TestIdentityStillHidesUnresolvableEntity(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	if _, err := New(srv.URL).Identity(context.Background(), "55555555-5555-5555-5555-555555555555", "", ""); !errors.Is(err, ErrNotVisible) {
		t.Fatalf("不可见实体应返回 ErrNotVisible，实际 err=%v", err)
	}
}

// AliasSet：{canonical + 全部请求 ID} 去重，空串丢弃（与互动侧同一兼容口径）。
func TestAliasSetDedups(t *testing.T) {
	got := AliasSet("d", "a", "d", "", "b", "a")
	want := []string{"a", "d", "b"}
	if len(got) != len(want) {
		t.Fatalf("AliasSet 去重不符：%v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("AliasSet 顺序不符：%v", got)
		}
	}
	if got := AliasSet("d", "d"); len(got) != 1 || got[0] != "d" {
		t.Fatalf("单 ID 应退化为自身：%v", got)
	}
}
