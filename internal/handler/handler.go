// Package handler 暴露存储服务的 HTTP 契约：/api/storage/*。
// 契约以 metafusion-docs 的 docs/api-storage.md 为准（内容寻址 + 预签名直传 + 绑定用途），
// 绑定只描述"文件是谁的什么用途"，收录位置仍留在目录侧的 locator。
package handler

import (
	"context"
	"errors"
	"log"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/MoeclubM/metafusion-storage/internal/auth"
	"github.com/MoeclubM/metafusion-storage/internal/catalog"
	"github.com/MoeclubM/metafusion-storage/internal/config"
	"github.com/MoeclubM/metafusion-storage/internal/objects"
	"github.com/MoeclubM/metafusion-storage/internal/store"
)

var (
	shaPattern  = regexp.MustCompile("^[0-9a-f]{64}$")
	codePattern = regexp.MustCompile("^[a-z][a-z0-9_]{0,31}$")
)

const defaultRole = "master_archive"

type Handler struct {
	db       *store.Store
	objects  *objects.Store
	catalog  *catalog.Client
	verifier *auth.Verifier
	cfg      config.Config
	log      *log.Logger
}

func New(db *store.Store, objs *objects.Store, cat *catalog.Client, verifier *auth.Verifier, cfg config.Config) *Handler {
	return &Handler{db: db, objects: objs, catalog: cat, verifier: verifier, cfg: cfg, log: log.Default()}
}

// Register 挂载契约路由。读接口允许匿名（可见性由目录实体决定），写接口一律要求登录。
func (h *Handler) Register(r *gin.Engine) {
	v := h.verifier
	api := r.Group("/api/storage")
	{
		api.POST("/upload/initiate", v.Required(), h.initiateUpload)
		api.POST("/upload/complete", v.Required(), h.completeUpload)
		api.PUT("/upload/stream/:assetId", v.Required(), h.streamUpload)
		api.POST("/bind", v.Required(), h.bind)
		api.DELETE("/bindings/:id", v.Required(), h.unbind)
		api.POST("/verify-hash", v.Middleware(), h.verifyHash)
		api.GET("/assets/:id", v.Middleware(), h.getAsset)
		api.GET("/assets/:id/content", v.Middleware(), h.assetContent)
		api.GET("/entities/:id/files", v.Middleware(), h.listEntityFiles)
		api.GET("/download/:assetId", v.Middleware(), h.download)
		api.GET("/stats", v.Required(), h.stats)
	}
}

func fail(c *gin.Context, status int, code string) {
	c.JSON(status, gin.H{"error": code})
}

// validID 报告路径或载荷里的 id 是否是合法 uuid。存储侧的所有 id 都是 uuid 主键，
// 非法字面量必须按"不存在"处理：直接送进 uuid 列只会拿到 pq 的解析错误，
// 再被兜成 500 module_error（契约里没有这个状态码，线上可复现）。
func validID(id string) bool {
	_, err := uuid.Parse(id)
	return err == nil
}

func (h *Handler) credentials(c *gin.Context) (string, string) {
	bearer := ""
	if authz := strings.TrimSpace(c.GetHeader("Authorization")); len(authz) > 7 && strings.EqualFold(authz[:7], "bearer ") {
		bearer = strings.TrimSpace(authz[7:])
	}
	cookie := ""
	if ck, err := c.Request.Cookie("mf_session"); err == nil {
		cookie = ck.Value
	}
	return bearer, cookie
}

// visibleEntity 通过目录服务确认实体可见，并返回权威 kind。
// 存储侧不缓存目录结论，也不直连目录库；可见性规则只有 catalog 一处实现。
func (h *Handler) visibleEntity(c *gin.Context, entityID string) (string, bool) {
	if _, err := uuid.Parse(entityID); err != nil {
		return "", false
	}
	bearer, cookie := h.credentials(c)
	kind, ok := h.catalog.Visible(c.Request.Context(), entityID, bearer, cookie)
	if !ok {
		return "", false
	}
	return kind, true
}

func normalizeRole(role string) string {
	role = strings.ToLower(strings.TrimSpace(role))
	if role == "" {
		return defaultRole
	}
	if !codePattern.MatchString(role) {
		return ""
	}
	return role
}

type initiateRequest struct {
	FileName         string `json:"file_name"`
	FileSize         int64  `json:"file_size"`
	SHA256Hash       string `json:"sha256_hash"`
	MimeType         string `json:"mime_type"`
	PartCount        int    `json:"part_count"`
	TargetEntityID   string `json:"target_entity_id"`
	TargetEntityType string `json:"target_entity_type"`
	BindingRole      string `json:"binding_role"`
}

type initiateResponse struct {
	IsInstantUpload bool           `json:"is_instant_upload"`
	AssetID         string         `json:"asset_id"`
	ObjectKey       string         `json:"object_key"`
	UploadID        string         `json:"upload_id,omitempty"`
	PresignedURLs   []string       `json:"presigned_urls,omitempty"`
	DirectUploadURL string         `json:"direct_upload_url,omitempty"`
	PartSizeHint    int64          `json:"part_size_hint,omitempty"`
	ExpiresAt       time.Time      `json:"expires_at"`
	Asset           *store.Asset   `json:"asset,omitempty"`
	Binding         *store.Binding `json:"binding,omitempty"`
}

// initiateUpload 是直传第一步：命中 sha256 即秒传，否则签发直传地址；
// 同一 sha256 的未完成上传由上传者本人续传，避免两个客户端互相覆盖。
func (h *Handler) initiateUpload(c *gin.Context) {
	var in initiateRequest
	if err := c.ShouldBindJSON(&in); err != nil {
		fail(c, 400, "invalid_payload")
		return
	}
	in.FileName = strings.TrimSpace(in.FileName)
	in.SHA256Hash = strings.ToLower(strings.TrimSpace(in.SHA256Hash))
	if in.FileName == "" || len(in.FileName) > 255 || !shaPattern.MatchString(in.SHA256Hash) || in.FileSize < 0 {
		fail(c, 400, "invalid_payload")
		return
	}
	if in.PartCount <= 0 {
		in.PartCount = 1
	}
	if in.PartCount > h.cfg.MaxPartCount {
		fail(c, 400, "too_many_parts")
		return
	}
	role := normalizeRole(in.BindingRole)
	if role == "" {
		fail(c, 400, "invalid_binding_role")
		return
	}
	if in.MimeType == "" {
		in.MimeType = "application/octet-stream"
	}
	targetKind := ""
	if in.TargetEntityID != "" {
		kind, ok := h.visibleEntity(c, in.TargetEntityID)
		if !ok {
			fail(c, 404, "not_found")
			return
		}
		targetKind = kind
		if in.TargetEntityType != "" && !strings.EqualFold(in.TargetEntityType, kind) {
			// 类型以目录服务的权威值为准，声明不符直接拒绝，避免绑定写错维度。
			fail(c, 400, "invalid_target_type")
			return
		}
	}

	p := auth.Current(c)
	ctx := c.Request.Context()

	// 命中分两种，判据必须分开：
	//  1. **已验证**的资产才能秒传（complete 态由 CompleteAsset 保证 hash_verified=true）；
	//  2. 未验证的未完成资产（上传中、或回读校验失败过）不能秒传，但必须按
	//     "同一 sha256 的未完成上传由上传者本人续传"的既有口径继续处理——
	//     校验失败的上传者重传正确内容才能收尾。若这里直接当"不存在"去新建资产，
	//     就会撞上 assets_sha256 唯一索引（那行 pending 占位行还在），
	//     结果是这个 sha256 被一次失败上传永久占死，谁也传不了。
	asset, err := h.db.VerifiedAssetByHash(ctx, in.SHA256Hash)
	if errors.Is(err, store.ErrNotFound) {
		asset, err = h.db.AssetByHash(ctx, in.SHA256Hash)
	}
	switch {
	case err == nil && asset.Status == "complete":
		resp := initiateResponse{IsInstantUpload: true, AssetID: asset.ID, ObjectKey: asset.ObjectKey, Asset: &asset}
		if in.TargetEntityID != "" {
			b, berr := h.createBinding(ctx, asset.ID, in.TargetEntityID, targetKind, role, p.ID)
			if berr != nil {
				fail(c, 500, "module_error")
				return
			}
			resp.Binding = &b
		}
		c.JSON(200, resp)
		return
	case err == nil:
		// 续传/覆盖他人尚未完成的上传是跨用户处置，用 storage.asset.moderate
		// （拆分前这里是 role == admin：语义相同，只是改成认权限组）。
		if asset.UploaderID != p.ID && !p.Can(auth.PermissionAssetModerate) {
			fail(c, 409, "upload_in_progress")
			return
		}
		resp, rerr := h.presign(ctx, asset, in.PartCount, false)
		if rerr != nil {
			fail(c, 503, "storage_unavailable")
			return
		}
		c.JSON(200, resp)
		return
	case !errors.Is(err, store.ErrNotFound):
		fail(c, 500, "module_error")
		return
	}

	asset = store.Asset{
		ID:           uuid.NewString(),
		SHA256:       in.SHA256Hash,
		DeclaredSize: in.FileSize,
		MimeType:     in.MimeType,
		FileName:     in.FileName,
		ObjectKey:    h.objects.KeyFor(in.SHA256Hash, in.FileName),
		Status:       "pending",
		UploaderID:   p.ID,
	}
	if err = h.db.CreateAsset(ctx, asset); err != nil {
		fail(c, 500, "module_error")
		return
	}
	resp, rerr := h.presign(ctx, asset, in.PartCount, true)
	if rerr != nil {
		fail(c, 503, "storage_unavailable")
		return
	}
	// 新建资产时若同时给了目标实体，绑定在直传完成前后都成立：
	// 绑定只是"这份内容属于谁"，不依赖上传是否已落定。
	if in.TargetEntityID != "" {
		b, berr := h.createBinding(ctx, asset.ID, in.TargetEntityID, targetKind, role, p.ID)
		if berr != nil {
			fail(c, 500, "module_error")
			return
		}
		resp.Binding = &b
	}
	c.JSON(200, resp)
}

// presign 签发直传地址：分片上传建立（或复用）分片会话，本地对象模式返回服务端接收地址。
func (h *Handler) presign(ctx context.Context, asset store.Asset, partCount int, fresh bool) (initiateResponse, error) {
	resp := initiateResponse{AssetID: asset.ID, ObjectKey: asset.ObjectKey, ExpiresAt: time.Now().Add(h.cfg.PresignTTL)}
	if h.objects.Local() {
		resp.DirectUploadURL = "/api/storage/upload/stream/" + asset.ID
		return resp, nil
	}
	uploadID := asset.MultipartUploadID
	if partCount > 1 && (fresh || uploadID == "") {
		var err error
		uploadID, err = h.objects.NewParts(ctx, asset.ObjectKey, asset.MimeType, partCount)
		if err != nil {
			return resp, err
		}
		if err = h.db.SetUploadSession(ctx, asset.ID, uploadID); err != nil {
			return resp, err
		}
	}
	urls, err := h.objects.PresignParts(ctx, asset.ObjectKey, asset.MimeType, partCount, uploadID)
	if err != nil {
		return resp, err
	}
	resp.UploadID = uploadID
	resp.PresignedURLs = urls
	if partCount > 1 && asset.DeclaredSize > 0 {
		resp.PartSizeHint = (asset.DeclaredSize + int64(partCount) - 1) / int64(partCount)
	}
	return resp, nil
}

// createBinding 写一条"文件 → 实体"的绑定。
func (h *Handler) createBinding(ctx context.Context, assetID, entityID, kind, role, userID string) (store.Binding, error) {
	b := store.Binding{
		ID:             uuid.NewString(),
		AssetID:        assetID,
		TargetEntityID: entityID,
		TargetKind:     kind,
		BindingRole:    role,
		CreatedBy:      userID,
	}
	if err := h.db.Bind(ctx, b); err != nil {
		return store.Binding{}, err
	}
	return b, nil
}

// canManageAsset 是纯函数：上传者本人，或持有 storage.asset.moderate 的审核者，
// 可完成/绑定/解绑。前者是所有权（自己的文件自己收尾），后者是审核权
// （代替拆分前的 role == admin，见 internal/auth/permission.go 的备注）。
func canManageAsset(p *auth.Principal, uploader string) bool {
	return p != nil && (p.ID == uploader || p.Can(auth.PermissionAssetModerate))
}

func (h *Handler) completeUpload(c *gin.Context) {
	var in struct {
		AssetID  string         `json:"asset_id"`
		UploadID string         `json:"upload_id"`
		Parts    []objects.Part `json:"parts"`
	}
	if err := c.ShouldBindJSON(&in); err != nil || in.AssetID == "" {
		fail(c, 400, "invalid_payload")
		return
	}
	if !validID(in.AssetID) {
		fail(c, 404, "not_found")
		return
	}
	p := auth.Current(c)
	ctx := c.Request.Context()
	asset, err := h.db.Asset(ctx, in.AssetID)
	if errors.Is(err, store.ErrNotFound) {
		fail(c, 404, "not_found")
		return
	}
	if err != nil {
		fail(c, 500, "module_error")
		return
	}
	if !canManageAsset(p, asset.UploaderID) {
		fail(c, 403, "forbidden")
		return
	}
	if asset.Status == "complete" {
		c.JSON(200, gin.H{"asset": asset, "already_complete": true})
		return
	}
	// 客户端声明的大小已经超上限时不必先合并：回读校验注定失败，
	// 提前失败也避免为一份不可能发布的资产在对象存储里留下碎片。
	if limit := h.objects.VerifyMaxBytes(); limit > 0 && asset.DeclaredSize > limit {
		fail(c, 413, "hash_verify_too_large")
		return
	}
	uploadID := in.UploadID
	if uploadID == "" {
		uploadID = asset.MultipartUploadID
	}
	size, err := h.objects.CompleteUpload(ctx, asset.ObjectKey, uploadID, in.Parts)
	if err != nil {
		fail(c, 400, "upload_incomplete")
		return
	}
	if h.objects.Local() {
		// 本地模式没有预签名直传：对象由 /upload/stream 边收边算摘要后落定，
		// complete 只做幂等确认（该路径已在 streamUpload 里验过摘要）。
		c.JSON(200, gin.H{"asset": asset})
		return
	}
	if asset.DeclaredSize > 0 && size != asset.DeclaredSize {
		_ = h.objects.AbortUpload(ctx, asset.ObjectKey, uploadID)
		fail(c, 409, "size_mismatch")
		return
	}
	// 预签名路径的内容从未经过服务端：落定前必须整份回读、重算 sha256 再比对。
	// 大小一致不足以证明内容一致——等长的另一份内容完全可能挂在同一个 sha256 键上。
	started := time.Now()
	digest, read, verr := h.objects.VerifyHash(ctx, asset.ObjectKey, asset.SHA256)
	if verr != nil {
		// 校验没通过就没有"完成"可谈：资产留在 pending（既不参与秒传也不可下载），
		// 摘要不符的原始对象也一并中止/删除，不给内容寻址键留污染对象。
		reason, status := verifyError(verr)
		h.log.Printf("storage: asset %s 回读校验失败 code=%s size=%d read=%d elapsed=%s err=%v",
			asset.ID, reason, size, read, time.Since(started), verr)
		if !errors.Is(verr, objects.ErrVerifyTooLarge) {
			_ = h.objects.AbortUpload(ctx, asset.ObjectKey, uploadID)
		}
		_ = h.objects.Remove(ctx, asset.ObjectKey)
		if merr := h.db.MarkHashMismatch(ctx, asset.ID, reason); merr != nil {
			h.log.Printf("storage: asset %s 记录校验失败原因出错: %v", asset.ID, merr)
		}
		fail(c, status, reason)
		return
	}
	if err = h.db.MarkHashVerified(ctx, asset.ID, read); err != nil {
		fail(c, 500, "module_error")
		return
	}
	if err = h.db.CompleteAsset(ctx, asset.ID, read); err != nil {
		// 到这里 hash_verified 已经为真，ErrAssetUnverified 只会在数据被外部改坏时出现。
		fail(c, 500, "module_error")
		return
	}
	asset.Status = "complete"
	asset.SizeBytes = read
	asset.HashVerified = true
	h.log.Printf("storage: asset %s 回读校验通过 sha256=%s size=%d elapsed=%s", asset.ID, digest, read, time.Since(started))
	c.JSON(200, gin.H{"asset": asset})
}

// verifyError 把回读校验的失败原因翻成对外错误码与状态码（纯函数，便于离线固定口径）：
// 摘要不符是客户端内容错了（409），超限与超时是这份对象太大/太慢（413、408）。
// 其它读取失败不是"内容错"，按 503 处理，避免把对象存储故障说成上传者的问题。
func verifyError(err error) (code string, status int) {
	switch {
	case errors.Is(err, objects.ErrHashMismatch):
		return "hash_mismatch", 409
	case errors.Is(err, objects.ErrVerifyTooLarge):
		return "hash_verify_too_large", 413
	case errors.Is(err, objects.ErrVerifyTimeout):
		return "verify_timeout", 408
	default:
		return "storage_unavailable", 503
	}
}

// streamUpload 是服务端接收路径：本地对象模式的主要上传方式，
// 同时也可作为预签名不可用时的兜底。落盘前流式计算 sha256 并与声明比对。
func (h *Handler) streamUpload(c *gin.Context) {
	if !validID(c.Param("assetId")) {
		fail(c, 404, "not_found")
		return
	}
	p := auth.Current(c)
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
	if !canManageAsset(p, asset.UploaderID) {
		fail(c, 403, "forbidden")
		return
	}
	if h.cfg.MaxUploadMB > 0 {
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, int64(h.cfg.MaxUploadMB)<<20)
	}
	// PutStream 在发布对象之前就比对声明摘要：不符时对象根本没进对象存储，
	// 因此这里只把 ErrHashMismatch 翻成 409，不需要再补一次"读完才比对"的清理。
	size, _, err := h.objects.PutStream(ctx, asset.ObjectKey, c.Request.Body, asset.SHA256)
	if errors.Is(err, objects.ErrHashMismatch) {
		fail(c, 409, "hash_mismatch")
		return
	}
	if err != nil {
		fail(c, 400, "upload_failed")
		return
	}
	if err := h.db.MarkHashVerified(ctx, asset.ID, size); err != nil {
		fail(c, 500, "module_error")
		return
	}
	if err := h.db.CompleteAsset(ctx, asset.ID, size); err != nil {
		fail(c, 500, "module_error")
		return
	}
	asset.Status = "complete"
	asset.SizeBytes = size
	asset.HashVerified = true
	c.JSON(200, gin.H{"asset": asset})
}

func (h *Handler) bind(c *gin.Context) {
	var in struct {
		AssetID          string `json:"asset_id"`
		TargetEntityID   string `json:"target_entity_id"`
		TargetEntityType string `json:"target_entity_type"`
		BindingRole      string `json:"binding_role"`
	}
	if err := c.ShouldBindJSON(&in); err != nil || in.AssetID == "" || in.TargetEntityID == "" {
		fail(c, 400, "invalid_payload")
		return
	}
	role := normalizeRole(in.BindingRole)
	if role == "" {
		fail(c, 400, "invalid_binding_role")
		return
	}
	p := auth.Current(c)
	ctx := c.Request.Context()
	asset, err := h.db.Asset(ctx, in.AssetID)
	if errors.Is(err, store.ErrNotFound) {
		fail(c, 404, "not_found")
		return
	}
	if err != nil {
		fail(c, 500, "module_error")
		return
	}
	if !canManageAsset(p, asset.UploaderID) {
		fail(c, 403, "forbidden")
		return
	}
	kind, ok := h.visibleEntity(c, in.TargetEntityID)
	if !ok {
		fail(c, 404, "not_found")
		return
	}
	if in.TargetEntityType != "" && !strings.EqualFold(in.TargetEntityType, kind) {
		fail(c, 400, "invalid_target_type")
		return
	}
	b, err := h.createBinding(ctx, asset.ID, in.TargetEntityID, kind, role, p.ID)
	if err != nil {
		fail(c, 500, "module_error")
		return
	}
	c.JSON(200, gin.H{"binding": b})
}

func (h *Handler) unbind(c *gin.Context) {
	if !validID(c.Param("id")) {
		fail(c, 404, "not_found")
		return
	}
	p := auth.Current(c)
	ctx := c.Request.Context()
	b, err := h.db.Binding(ctx, c.Param("id"))
	if errors.Is(err, store.ErrNotFound) {
		fail(c, 404, "not_found")
		return
	}
	if err != nil {
		fail(c, 500, "module_error")
		return
	}
	asset, err := h.db.Asset(ctx, b.AssetID)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		fail(c, 500, "module_error")
		return
	}
	// 绑定创建者、文件上传者或管理员可以解绑：绑定是"关系"，纠错不应被上传者身份卡住。
	if !canManageAsset(p, asset.UploaderID) && b.CreatedBy != p.ID {
		fail(c, 403, "forbidden")
		return
	}
	if err = h.db.Unbind(ctx, b.ID); err != nil {
		fail(c, 500, "module_error")
		return
	}
	c.JSON(200, gin.H{"ok": true})
}
