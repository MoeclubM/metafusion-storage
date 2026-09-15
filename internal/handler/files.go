package handler

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/MoeclubM/metafusion-storage/internal/auth"
	"github.com/MoeclubM/metafusion-storage/internal/store"
)

// maxBindingProbe 限制一次读取鉴权最多问目录服务几次：绑定是"文件属于谁"的少量元数据，
// 异常多的绑定不值得为一次下载打穿目录服务。
const maxBindingProbe = 20

// readable 是文件读取的唯一判定：上传者本人或持 storage.asset.moderate 的审核者直通，
// 其余人只要**任一**绑定目标可见即可读（直通档位同 canManageAsset，替换拆分前的 role == admin）。
// 与下载、预览、哈希校验共用同一判定，避免同一份文件在不同接口上口径不同。
func (h *Handler) readable(c *gin.Context, asset store.Asset) bool {
	p := auth.Current(c)
	if canManageAsset(p, asset.UploaderID) {
		return true
	}
	if asset.Status != "complete" {
		return false
	}
	bindings, err := h.db.BindingsForAsset(c.Request.Context(), asset.ID)
	if err != nil {
		return false
	}
	if len(bindings) > maxBindingProbe {
		bindings = bindings[:maxBindingProbe]
	}
	bearer, cookie := h.credentials(c)
	for _, b := range bindings {
		if _, ok := h.catalog.Visible(c.Request.Context(), b.TargetEntityID, bearer, cookie); ok {
			return true
		}
	}
	return false
}

func (h *Handler) getAsset(c *gin.Context) {
	ctx := c.Request.Context()
	asset, err := h.db.Asset(ctx, c.Param("id"))
	if errors.Is(err, store.ErrNotFound) {
		fail(c, 404, "not_found")
		return
	}
	if err != nil {
		fail(c, 500, "module_error")
		return
	}
	if !h.readable(c, asset) {
		fail(c, 404, "not_found")
		return
	}
	bindings, err := h.db.BindingsForAsset(ctx, asset.ID)
	if err != nil {
		fail(c, 500, "module_error")
		return
	}
	c.JSON(200, gin.H{"asset": asset, "bindings": bindings})
}

// listEntityFiles 是"这个介质/轨道/表达上挂了哪些文件"的入口。
// 实体可见性由目录服务判定，绑定与文件元数据由存储服务提供。
func (h *Handler) listEntityFiles(c *gin.Context) {
	entityID := c.Param("id")
	kind, ok := h.visibleEntity(c, entityID)
	if !ok {
		fail(c, 404, "not_found")
		return
	}
	files, err := h.db.BindingsForEntity(c.Request.Context(), entityID)
	if err != nil {
		fail(c, 500, "module_error")
		return
	}
	c.JSON(200, gin.H{"target_entity_id": entityID, "target_kind": kind, "files": files})
}

func (h *Handler) download(c *gin.Context) {
	ctx := c.Request.Context()
	asset, err := h.db.Asset(ctx, c.Param("assetId"))
	if errors.Is(err, store.ErrNotFound) {
		fail(c, 404, "not_found")
		return
	}
	if err != nil {
		fail(c, 500, "module_error")
		return
	}
	// 不可读一律回 404：不区分"无权限"与"不存在"，避免泄露他人上传的存在性。
	if !h.readable(c, asset) || asset.Status != "complete" {
		fail(c, 404, "not_found")
		return
	}
	c.Header("Cache-Control", "private, no-store")
	if !h.objects.Local() {
		url, expires, err := h.objects.PresignDownload(ctx, asset.ObjectKey, asset.FileName)
		if err != nil {
			fail(c, 503, "storage_unavailable")
			return
		}
		c.JSON(200, gin.H{
			"asset_id":     asset.ID,
			"file_name":    asset.FileName,
			"size_bytes":   asset.SizeBytes,
			"sha256":       asset.SHA256,
			"download_url": url,
			"expires_at":   expires,
		})
		return
	}
	// 本地对象模式：没有可签名对象存储，直接由本服务流式下发。
	obj, size, err := h.objects.Open(ctx, asset.ObjectKey)
	if err != nil {
		fail(c, 503, "storage_unavailable")
		return
	}
	defer obj.Close()
	c.Header("Content-Type", asset.MimeType)
	c.Header("Content-Disposition", "attachment; filename=\""+asset.FileName+"\"")
	http.ServeContent(c.Writer, c.Request, asset.FileName, time.Time{}, obj)
	_ = size
}

// verifyHash 两种用法：只给 sha256 是秒传探测（返回是否已存在），
// 给 asset_id 则读回对象重算摘要，与声明的 sha256 比对并记录校验结果。
func (h *Handler) verifyHash(c *gin.Context) {
	var in struct {
		AssetID    string `json:"asset_id"`
		SHA256Hash string `json:"sha256_hash"`
	}
	if err := c.ShouldBindJSON(&in); err != nil {
		fail(c, 400, "invalid_payload")
		return
	}
	ctx := c.Request.Context()
	if sha := strings.ToLower(strings.TrimSpace(in.SHA256Hash)); sha != "" {
		if !shaPattern.MatchString(sha) {
			fail(c, 400, "invalid_payload")
			return
		}
		asset, err := h.db.AssetByHash(ctx, sha)
		if err != nil || !h.readable(c, asset) {
			// 无权读取的内容一律当作不存在。
			c.JSON(200, gin.H{"exists": false})
			return
		}
		c.JSON(200, gin.H{"exists": true, "asset_id": asset.ID, "status": asset.Status, "size_bytes": asset.SizeBytes})
		return
	}
	if in.AssetID == "" {
		fail(c, 400, "invalid_payload")
		return
	}
	asset, err := h.db.Asset(ctx, in.AssetID)
	if errors.Is(err, store.ErrNotFound) {
		fail(c, 404, "not_found")
		return
	}
	if err != nil {
		fail(c, 500, "module_error")
		return
	}
	if !h.readable(c, asset) {
		fail(c, 404, "not_found")
		return
	}
	digest, size, err := h.objects.HashOf(ctx, asset.ObjectKey)
	if err != nil {
		fail(c, 503, "storage_unavailable")
		return
	}
	verified := digest == asset.SHA256
	_ = h.db.MarkHashVerified(ctx, asset.ID, verified, size)
	c.JSON(200, gin.H{
		"asset_id":        asset.ID,
		"sha256":          digest,
		"declared_sha256": asset.SHA256,
		"verified":        verified,
		"size_bytes":      size,
	})
}

func (h *Handler) stats(c *gin.Context) {
	// 全局容量是运营数据，跨所有上传者：用 storage.asset.moderate，
	// 与拆分前「仅管理员可看」一致（不是任何人都能从令牌拿到的公开统计）。
	if !auth.Current(c).Can(auth.PermissionAssetModerate) {
		fail(c, 403, "forbidden")
		return
	}
	assets, bytes, err := h.db.Stats(c.Request.Context())
	if err != nil {
		fail(c, 500, "module_error")
		return
	}
	c.JSON(200, gin.H{"assets": assets, "bytes": bytes})
}
