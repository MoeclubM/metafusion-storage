package catalog

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/MoeclubM/metafusion-storage/internal/auth"
)

// Client 是存储服务对元数据目录的唯一出口：只读实体可见性与身份兜底解析。
// 存储侧不复制目录数据、不直连目录库，可见性规则只有 catalog 一处实现。
type Client struct {
	base string
	http *http.Client
}

func New(base string) *Client {
	return &Client{
		base: strings.TrimRight(base, "/"),
		http: &http.Client{Timeout: 5 * time.Second},
	}
}

// Visible 询问目录服务：该实体对当前请求者是否可见；可见则返回实体 kind。
// 令牌原样转发，草稿/待审条目的可见性判断仍然只由目录服务决定。
func (c *Client) Visible(ctx context.Context, entityID, bearer, cookie string) (string, bool) {
	if c.base == "" || entityID == "" {
		return "", false
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+"/api/catalog/entities/"+entityID, nil)
	if err != nil {
		return "", false
	}
	c.decorate(req, bearer, cookie)
	resp, err := c.http.Do(req)
	if err != nil {
		return "", false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", false
	}
	var entity struct {
		Kind string `json:"kind"`
	}
	if err = json.NewDecoder(resp.Body).Decode(&entity); err != nil {
		return "", false
	}
	return entity.Kind, true
}

// Resolve 用会话令牌换身份（迁移期兜底）。账号服务拆分完成后，
// 各服务只验 JWT，这条链路可以直接关掉，不需要改业务代码。
func (c *Client) Resolve(ctx context.Context, bearer, cookie string) (*auth.Principal, bool) {
	if c.base == "" || (bearer == "" && cookie == "") {
		return nil, false
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+"/api/auth/me", nil)
	if err != nil {
		return nil, false
	}
	c.decorate(req, bearer, cookie)
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, false
	}
	var user struct {
		ID       string `json:"id"`
		Username string `json:"username"`
		Role     string `json:"role"`
	}
	if err = json.NewDecoder(resp.Body).Decode(&user); err != nil || user.ID == "" {
		return nil, false
	}
	return &auth.Principal{ID: user.ID, Username: user.Username, Role: user.Role}, true
}

func (c *Client) decorate(req *http.Request, bearer, cookie string) {
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	if cookie != "" {
		req.AddCookie(&http.Cookie{Name: "mf_session", Value: cookie})
	}
}
