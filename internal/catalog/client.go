package catalog

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

// Client 是存储服务对元数据目录的唯一出口：只读实体可见性。
// 存储侧不复制目录数据、不直连目录库，可见性规则只有 catalog 一处实现；
// 身份解析也不在这里——那是账号服务的事（见 internal/auth 的 SessionClient）。
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
//
// 已合并的旧身份直接取会 404（合并后旧 id 不再可见），此时再用 /resolve 跟随重定向：
// 合并只广播事件、不改写别人表里的引用，因此"跟随重定向"是引用方自己的责任，
// 否则绑定在旧身份上的文件会从实体文件列表里静默消失。
func (c *Client) Visible(ctx context.Context, entityID, bearer, cookie string) (string, bool) {
	if c.base == "" || entityID == "" {
		return "", false
	}
	if kind, ok := c.fetchKind(ctx, entityID, bearer, cookie); ok {
		return kind, true
	}
	return c.fetchKind(ctx, entityID+"/resolve", bearer, cookie)
}

// fetchKind 取一次实体端点（suffix 为空即 GET /entities/{id}，为 /resolve 时跟随合并重定向）。
func (c *Client) fetchKind(ctx context.Context, path, bearer, cookie string) (string, bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+"/api/catalog/entities/"+path, nil)
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
func (c *Client) decorate(req *http.Request, bearer, cookie string) {
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	if cookie != "" {
		req.AddCookie(&http.Cookie{Name: "mf_session", Value: cookie})
	}
}
