package handler

import (
	"github.com/gin-gonic/gin"

	"github.com/MoeclubM/metafusion-storage/internal/audit"
	"github.com/MoeclubM/metafusion-storage/internal/auth"
	"github.com/MoeclubM/metafusion-storage/internal/store"
)

// auditActions 是写路由的动作码注册表：键是「方法 + 路由模板」，与 gin 的 c.FullPath() 同形，
// 值是按契约 §2 命名的稳定机器码（<域>.<过去式动作>，全小写 + 下划线，只增不改）。
//
// 本服务**不存在**的写操作（清单里没有对应动作码，也没有豁免条目，因为没有可挂的端点）：
//   - 删除资产/对象：没有 DELETE /api/storage/assets/:id，也没有对象删除端点；
//     唯一的删除是 DELETE /api/storage/bindings/:id（解绑，已登记 binding.removed）；
//   - 审核/处置他人资产：没有审核端点，"审核"只体现为 storage.asset.moderate 在既有写路由内的判定
//     （见 handler.go 的 canManageAsset），因此没有 moderation.* 动作码。
//
// 新增写端点时必须同时在这里登记动作码，否则 TestWriteRoutesAreAudited 会失败。
var auditActions = map[string]string{
	"POST /api/storage/upload/initiate":       "asset.upload_initiated",
	"POST /api/storage/upload/complete":       "asset.upload_completed",
	"PUT /api/storage/upload/stream/:assetId": "asset.upload_streamed",
	"POST /api/storage/bind":                  "binding.created",
	"DELETE /api/storage/bindings/:id":        "binding.removed",
}

// auditExempt 是"是写方法但刻意不审计"的路由 → 一句理由。中间件不读它，
// 它是写路由覆盖守卫测试的输入：写路由要么登记动作码、要么在这里写明为什么不审计。
var auditExempt = map[string]string{
	"POST /api/storage/verify-hash": "读语义：秒传探测与摘要回读校验，不改变资产状态；" +
		"探测允许匿名，写审计等于给只读探测开一个刷表入口；被拒时（401/503）同样不记——契约 §7 的边界是" +
		"「写操作留痕」而不是「所有非 GET 请求留痕」；唯一的写副作用是回读摘要不符时" +
		"给未发布资产写 fail_reason 诊断字段，不是业务写动作",
}

// auditActor 从请求上下文取操作者。存储只验签，区分不了"会话令牌"与"OAuth 令牌"（契约 §7），
// 只能给 pat / session 这两个近似值；没有身份时按 anonymous 记。
func auditActor(c *gin.Context) audit.Actor {
	p := auth.Current(c)
	if p == nil {
		return audit.Actor{CredentialType: audit.CredentialAnonymous}
	}
	credential := audit.CredentialSession
	if p.FromPAT {
		credential = audit.CredentialPAT
	}
	return audit.Actor{UserID: p.ID, Username: p.Username, CredentialType: credential}
}

// auditMiddleware 是 api 组的审计中间件：挂在写路由之前，只有登记了动作码的写请求才留痕。
// 未接线记录器（handler.audit 为 nil）时只回写 X-Request-Id、不写库——离线单测走的就是这条路。
func (h *Handler) auditMiddleware() gin.HandlerFunc {
	return audit.Middleware(audit.Options{
		Recorder: h.audit,
		Actions:  auditActions,
		Exempt:   auditExempt,
		Actor:    auditActor,
	})
}

// UseAudit 接线审计记录器。New 的签名保持不变（既有测试与 main 都在用），
// 记录器单独接是因为它需要数据库连接，而 handler 的其余依赖在离线测试里可以给零值。
func (h *Handler) UseAudit(rec *audit.Recorder) *Handler {
	h.audit = rec
	return h
}

// assetSummary 是审计摘要里的资产元数据：只放元数据（哈希/大小/类型/文件名），
// 不放内容，也不放任何对象存储地址——预签名 URL 本身是凭据，绝不能进审计。
func assetSummary(a store.Asset) map[string]any {
	return map[string]any{
		"asset_id":      a.ID,
		"sha256":        a.SHA256,
		"size_bytes":    a.SizeBytes,
		"declared_size": a.DeclaredSize,
		"mime_type":     a.MimeType,
		"file_name":     a.FileName,
		"status":        a.Status,
		// 键名刻意用 verified 而不是 hash_verified：脱敏的子串黑名单含 "hash"，
		// 叫 hash_verified 的键会被整条替换成 [redacted]，摘要就白写了。
		"verified": a.HashVerified,
	}
}

// assetTransition 是"资产状态迁移"的摘要形状：变更前后用 {"from","to"} 表达（契约 §1 的 changes 语义）。
func assetTransition(before string, after store.Asset, extra map[string]any) map[string]any {
	changes := assetSummary(after)
	changes["status"] = map[string]any{"from": before, "to": after.Status}
	for k, v := range extra {
		changes[k] = v
	}
	return changes
}

// auditAsset 记录"这次请求动了哪一份资产"及其元数据摘要；extra 里的同名键覆盖基础摘要。
// 失败路径也调它：被拒的写尝试同样要知道对象是谁（契约 §6.2 要求失败也留痕）。
func (h *Handler) auditAsset(c *gin.Context, a store.Asset, extra map[string]any) {
	changes := assetSummary(a)
	for k, v := range extra {
		changes[k] = v
	}
	audit.Describe(c, audit.Detail{TargetType: "asset", TargetID: a.ID, Changes: changes})
}
