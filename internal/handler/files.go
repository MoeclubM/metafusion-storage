package handler

import (
	"errors"
	"mime"
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
	if !validID(c.Param("id")) {
		fail(c, 404, "not_found")
		return
	}
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
	if !validID(c.Param("assetId")) {
		fail(c, 404, "not_found")
		return
	}
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
	c.Header("Content-Disposition", contentDisposition(asset.FileName))
	http.ServeContent(c.Writer, c.Request, asset.FileName, time.Time{}, obj)
	_ = size
}

// contentDisposition 生成下载响应头。文件名是上传者提供的任意字符串，
// 直接拼进 header 会让名字里的引号改写 disposition 的其它参数（非 ASCII 名
// 也是一串裸字节）；交给 mime.FormatMediaType 编码，必要时走 RFC 2231 的
// filename*。对象存储模式那一侧由 objects.mimeDisposition 负责，口径一致。
func contentDisposition(name string) string {
	if name == "" {
		return "attachment"
	}
	if v := mime.FormatMediaType("attachment", map[string]string{"filename": name}); v != "" {
		return v
	}
	return "attachment"
}

// verifyHash 两种用法：只给 sha256 是秒传探测（返回是否已存在），
// 给 asset_id 则读回对象重算摘要，与声明的 sha256 比对。
//
// 探测（sha 分支）允许匿名：它只回答"库里有没有这份内容"，判定与 initiate 同一口径
// （hash_verified=true），未验证的命中按不存在返回。
// 按 asset_id 校验必须登录：它要整份回读对象（成本随对象大小增长，且受同一套上限约束）
// 并写回校验结论，是"上传者/审核者维护自己资产"的动作，不是公开只读接口。
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
		// 秒传探测与 initiate 同一条判据：只有服务端验过内容的资产才算"已有这份内容"。
		// 未验证的命中按不存在返回，客户端会走正常上传，不会白等一份错内容。
		asset, err := h.db.VerifiedAssetByHash(ctx, sha)
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
	// 字面量非法即格式错误，先于鉴权回 404（与其余按 id 查库的入口一致，
	// 也保住契约里"非法 id 不得被兜成 500"的口径）；合法 id 才要求登录。
	if !validID(in.AssetID) {
		fail(c, 404, "not_found")
		return
	}
	if auth.Current(c) == nil {
		fail(c, 401, "unauthorized")
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
	digest, size, verr := h.objects.VerifyHash(ctx, asset.ObjectKey, "")
	if verr != nil {
		// 与 complete 同一套上限：超限/超时都是显式失败，不返回半份摘要。
		code, status := verifyError(verr)
		fail(c, status, code)
		return
	}
	verified := digest == asset.SHA256
	if !verified {
		// 回读发现键上的内容与声明不符：只把**尚未发布**的资产钉在失败态（不参与秒传），
		// 已经 complete 的资产不在这里降级——降级属于"内容坏了"的处置决定，
		// 不该由一个匿名可触发的接口顺手改掉线上可读资产的状态，只留日志供审计跟进。
		if asset.Status != "complete" {
			_ = h.db.MarkHashMismatch(ctx, asset.ID, "hash_mismatch")
		}
		h.log.Printf("storage: asset %s 回读摘要与声明不符 declared=%s actual=%s status=%s",
			asset.ID, asset.SHA256, digest, asset.Status)
	}
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
