package catalog

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// 合并只广播事件、不改写别人表里的引用：绑定在旧身份上的文件必须靠"跟随重定向"
// 继续可见，否则实体的文件列表会静默少掉一批。
func TestVisibleFollowsMergedIdentity(t *testing.T) {
	const oldID, newID = "11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222"
	var resolved bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/catalog/entities/" + oldID:
			w.WriteHeader(http.StatusNotFound)
		case "/api/catalog/entities/" + oldID + "/resolve":
			resolved = true
			_, _ = w.Write([]byte(`{"id":"` + newID + `","kind":"work"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	kind, ok := New(srv.URL).Visible(context.Background(), oldID, "", "")
	if !ok || !resolved || kind != "work" {
		t.Fatalf("未跟随合并重定向: ok=%v kind=%q resolved=%v", ok, kind, resolved)
	}
}

// 真正不可见的实体仍然返回 false：跟随重定向不能变成"更宽松的可见性"。
func TestVisibleStillHidesUnresolvableEntity(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	if _, ok := New(srv.URL).Visible(context.Background(), "33333333-3333-3333-3333-333333333333", "", ""); ok {
		t.Fatal("不可见实体不应返回可见")
	}
}
