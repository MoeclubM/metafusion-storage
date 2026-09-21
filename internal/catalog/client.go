package catalog

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/MoeclubM/metafusion-storage/internal/upstream"
)

// ErrNotVisible 报告目录服务**明确回答**"该实体对当前请求者不可见或不存在"。
//
// 它必须与"上游不可用"分开：旧实现两种情况的返回值都是 ok=false，于是目录服务一抖就被调用方
// 折成"没有这个实体"——绑定在它上面的文件会从实体文件列表里静默消失，故障对用户和运维都不可观测。
// 调用方按错误分工：errors.Is(err, ErrNotVisible) → 404，其它 error → 503 上游机器码。
var ErrNotVisible = errors.New("entity not visible")

// visiblePolicy 是"问一次实体可见性"的出站策略。可见性判定在请求路径上（每次下载、每个列表都问），
// 因此单次尝试与总预算都收得紧：两次尝试吸收瞬时抖动，持续失败交给熔断挡住，
// 不给目录服务"抖一下就等于所有文件都不存在"的机会。
func visiblePolicy() upstream.Policy {
	p := upstream.DefaultPolicy("catalog")
	p.Attempts = 2
	p.AttemptTimeout = 2 * time.Second
	p.Budget = 5 * time.Second
	p.BaseBackoff = 100 * time.Millisecond
	p.MaxBackoff = 500 * time.Millisecond
	p.Jitter = 0.5
	p.BreakerThreshold = 5
	p.BreakerOpenFor = 10 * time.Second
	return p
}

// Client 是存储服务对元数据目录的唯一出口：只读实体可见性。
// 存储侧不复制目录数据、不直连目录库，可见性规则只有 catalog 一处实现；
// 身份解析也不在这里——那是账号服务的事（见 internal/auth 的 SessionClient）。
type Client struct {
	base string
	up   *upstream.Client
}

func New(base string) *Client {
	return &Client{
		base: strings.TrimRight(base, "/"),
		up:   upstream.New(visiblePolicy()),
	}
}

// Upstream 暴露出站执行器给深探针：/ready?deep=1 必须复用请求路径上的同一个熔断器，
// 另建一个实例只会得到一个永远闭合的假状态。
func (c *Client) Upstream() *upstream.Client { return c.up }

// Visible 询问目录服务：该实体对当前请求者是否可见；可见则返回实体 kind。
// 令牌原样转发，草稿/待审条目的可见性判断仍然只由目录服务决定。
//
// error 非 nil 时**不能**当成"不可见"：只有 errors.Is(err, ErrNotVisible) 是目录服务的明确结论，
// 其余错误（超时/连接失败/5xx/熔断打开）表示这次问不到上游，调用方必须回 503 而不是 404。
//
// 已合并的旧身份直接取会 404（合并后旧 id 不再可见），此时再用 /resolve 跟随重定向：
// 合并只广播事件、不改写别人表里的引用，因此"跟随重定向"是引用方自己的责任，
// 否则绑定在旧身份上的文件会从实体文件列表里静默消失。
func (c *Client) Visible(ctx context.Context, entityID, bearer, cookie string) (string, error) {
	if c.base == "" || entityID == "" {
		// 目录地址未配置：存储侧无从判定可见性，只能按"不可见"对外（与拆分前口径一致）。
		return "", ErrNotVisible
	}
	kind, ok, err := c.fetchKind(ctx, entityID, bearer, cookie)
	if err != nil {
		return "", err
	}
	if ok {
		return kind, nil
	}
	kind, ok, err = c.fetchKind(ctx, entityID+"/resolve", bearer, cookie)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", ErrNotVisible
	}
	return kind, nil
}

// IdentityResolution 是目录侧统一身份解析契约（X01）的本地投影：canonical_id 为存活身份，
// aliases 为历史别名全集（GET /api/catalog/entities/{id}/identity，见目录
// lifecycle.go 的 IdentityResolution）：正向链上经过的旧 ID + 存活身份的反向遍历全集，
// 去重。读聚合按此集合展开（见 AliasSet）。
type IdentityResolution struct {
	CanonicalID string   `json:"canonical_id"`
	Aliases     []string `json:"aliases"`
	Entity      struct {
		ID   string `json:"id"`
		Kind string `json:"kind"`
	} `json:"entity"`
}

// Identity 问目录服务拿存活身份与 kind（X01 身份契约的只读投影，不改写任何引用）。
//
// 目录已合入 identity 端点时一次请求拿到 canonical；未合入（identity 404）时按旧
// /resolve 跟随合并重定向——两种路径都返回“请求 ID 对应的存活身份”。
// error 非 nil 时不能当成“不可见”：只有 errors.Is(err, ErrNotVisible) 是目录服务的明确结论，
// 其余错误表示问不到上游，调用方必须回 503 而不是空列表。
func (c *Client) Identity(ctx context.Context, entityID, bearer, cookie string) (IdentityResolution, error) {
	var zero IdentityResolution
	if c.base == "" || entityID == "" {
		return zero, ErrNotVisible
	}
	header := http.Header{}
	c.decorate(header, bearer, cookie)
	resp, err := c.up.Do(ctx, upstream.Request{
		Method: http.MethodGet,
		URL:    c.base + "/api/catalog/entities/" + entityID + "/identity",
		Header: header,
	})
	if err != nil {
		return zero, err
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusOK:
		var v IdentityResolution
		if err := json.NewDecoder(resp.Body).Decode(&v); err != nil {
			return zero, fmt.Errorf("catalog identity %s: 响应无法解析: %w", entityID, err)
		}
		if v.CanonicalID == "" || v.Entity.ID == "" {
			return zero, fmt.Errorf("catalog identity %s: 响应缺 canonical", entityID)
		}
		return v, nil
	case resp.StatusCode == http.StatusNotFound:
		// 身份端点不存在（旧目录）或实体不可见：走旧 /resolve 路径再判一次，
		// 不在这里直接报不可见——旧目录对一切 id 的 identity 都是 404。
		return c.identityViaResolve(ctx, entityID, bearer, cookie)
	default:
		return zero, fmt.Errorf("catalog identity %s: status %d", entityID, resp.StatusCode)
	}
}

// identityViaResolve 是 identity 端点缺失时的旧路径：本体可见即自身为存活身份，
// 否则跟随 /resolve 取合并后的存活身份与 kind（与 Visible 同口径，另取回 id）。
func (c *Client) identityViaResolve(ctx context.Context, entityID, bearer, cookie string) (IdentityResolution, error) {
	var zero IdentityResolution
	kind, ok, err := c.fetchKind(ctx, entityID, bearer, cookie)
	if err != nil {
		return zero, err
	}
	if ok {
		zero.CanonicalID, zero.Entity.ID, zero.Entity.Kind = entityID, entityID, kind
		return zero, nil
	}
	header := http.Header{}
	c.decorate(header, bearer, cookie)
	resp, err := c.up.Do(ctx, upstream.Request{
		Method: http.MethodGet,
		URL:    c.base + "/api/catalog/entities/" + entityID + "/resolve",
		Header: header,
	})
	if err != nil {
		return zero, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return zero, ErrNotVisible
	}
	var entity struct {
		ID   string `json:"id"`
		Kind string `json:"kind"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&entity); err != nil {
		return zero, fmt.Errorf("catalog entity %s/resolve: 响应无法解析: %w", entityID, err)
	}
	if entity.ID == "" {
		return zero, fmt.Errorf("catalog entity %s/resolve: 响应缺 id", entityID)
	}
	zero.CanonicalID, zero.Entity.ID, zero.Entity.Kind = entity.ID, entity.ID, entity.Kind
	if entity.ID != entityID {
		zero.Aliases = []string{entityID}
	}
	return zero, nil
}

// AliasSet 组装一次读取要覆盖的 ID 集合：{canonical + 请求 ID + 目录返回的别名全集}
// 去重（与互动 internal/catalog/client.go:AliasSet 同一口径）。目录 identity 契约返回
// 正向链与反向全集后，调用方把 aliases 原样传入即完成 X01 全量聚合。
func AliasSet(canonical string, requested ...string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, id := range append(append([]string{}, requested...), canonical) {
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	return out
}

// fetchKind 取一次实体端点（suffix 为空即 GET /entities/{id}，为 /resolve 时跟随合并重定向）。
// 第二个返回值是"目录服务明确回答了不可见/不存在"（非 200 的确定回答）；error 表示这次问不到上游。
func (c *Client) fetchKind(ctx context.Context, path, bearer, cookie string) (string, bool, error) {
	header := http.Header{}
	c.decorate(header, bearer, cookie)
	// 走 upstream.Client：超时分层（拨号/首字节/单次尝试/总预算）+ 有界重试 + 熔断。
	// 只有超时、连接失败、5xx、429 会被重试；404 这类 4xx 是上游的明确回答，一次就到底。
	resp, err := c.up.Do(ctx, upstream.Request{
		Method: http.MethodGet,
		URL:    c.base + "/api/catalog/entities/" + path,
		Header: header,
	})
	if err != nil {
		return "", false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", false, nil
	}
	var entity struct {
		Kind string `json:"kind"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&entity); err != nil {
		// 200 却读不出 kind：上游违约或响应被截断。按"问不到"报错（调用方回 503），
		// 折成"不可见"会把契约违约伪装成 404，谁也发现不了。
		return "", false, fmt.Errorf("catalog entity %s: 响应无法解析: %w", path, err)
	}
	return entity.Kind, true, nil
}

func (c *Client) decorate(header http.Header, bearer, cookie string) {
	if bearer != "" {
		header.Set("Authorization", "Bearer "+bearer)
	}
	if cookie != "" {
		header.Add("Cookie", (&http.Cookie{Name: "mf_session", Value: cookie}).String())
	}
}
