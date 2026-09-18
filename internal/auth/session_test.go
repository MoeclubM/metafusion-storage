package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// 存量不透明会话令牌的兜底必须问账号服务（会话表在它那里）：
// 凭据原样转发，身份由账号服务判定。
func TestSessionClientResolvesThroughAccountService(t *testing.T) {
	var gotAuth, gotCookie string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/auth/me" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		gotAuth = r.Header.Get("Authorization")
		if ck, err := r.Cookie("mf_session"); err == nil {
			gotCookie = ck.Value
		}
		_, _ = w.Write([]byte(`{"id":"u-1","username":"kana","role":"editor","groups":["community_moderator"],"permissions":["community.post.create","community.topic.pin"]}`))
	}))
	defer srv.Close()

	c := NewSessionClient(srv.URL)
	p, ok := c.Resolve(context.Background(), "opaque-token", "cookie-token")
	if !ok || p == nil || p.ID != "u-1" || p.Role != "editor" {
		t.Fatalf("身份解析失败: %v %+v", ok, p)
	}
	// 组与权限码必须一并带回：兜底解析和本地验签要给出同一个 Principal 形状，
	// 否则同一个人的能力会随"走哪条解析路径"而变。
	if len(p.Groups) != 1 || p.Groups[0] != "community_moderator" {
		t.Fatalf("groups 未透传: %+v", p.Groups)
	}
	if len(p.Permissions) != 2 || p.Permissions[0] != "community.post.create" || p.Permissions[1] != "community.topic.pin" {
		t.Fatalf("permissions 未透传: %+v", p.Permissions)
	}
	if gotAuth != "Bearer opaque-token" || gotCookie != "cookie-token" {
		t.Fatalf("凭据未原样透传: %q %q", gotAuth, gotCookie)
	}
}

// 未配置账号服务地址时不做任何请求（身份只认 JWT），也不会误判为已登录。
func TestSessionClientWithoutBaseIsInert(t *testing.T) {
	c := NewSessionClient("")
	if _, ok := c.Resolve(context.Background(), "t", ""); ok {
		t.Fatal("空地址不应解析出身份")
	}
}
