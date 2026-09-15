// Package handler 暴露存储服务的 HTTP 契约：/api/storage/*。
// 契约以 docs-site/docs/api-storage.md 的设计为准（内容寻址 + 预签名直传 + 绑定用途），
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
		api.GET("/entities/:id/files", v.Middleware(), h.listEntityFiles)
		api.GET("/download/:assetId", v.Middleware(), h.download)
		api.GET("/stats", v.Required(), h.stats)
	}
}

func fail(c *gin.Context, status int, code string) {
	c.JSON(status, gin.H{"error": code})
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
	asset, err := h.db.AssetByHash(ctx, in.SHA256Hash)
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
		// 本地模式由直传端点负责落定，complete 只做幂等确认。
		c.JSON(200, gin.H{"asset": asset})
		return
	}
	if asset.DeclaredSize > 0 && size != asset.DeclaredSize {
		_ = h.objects.AbortUpload(ctx, asset.ObjectKey, uploadID)
		fail(c, 409, "size_mismatch")
		return
	}
	if err = h.db.CompleteAsset(ctx, asset.ID, size); err != nil {
		fail(c, 500, "module_error")
		return
	}
	asset.Status = "complete"
	asset.SizeBytes = size
	c.JSON(200, gin.H{"asset": asset})
}

// streamUpload 是服务端接收路径：本地对象模式的主要上传方式，
// 同时也可作为预签名不可用时的兜底。落盘前流式计算 sha256 并与声明比对。
func (h *Handler) streamUpload(c *gin.Context) {
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
	size, digest, err := h.objects.PutStream(ctx, asset.ObjectKey, c.Request.Body)
	if err != nil {
		fail(c, 400, "upload_failed")
		return
	}
	if digest != asset.SHA256 {
		fail(c, 409, "hash_mismatch")
		return
	}
	if err := h.db.MarkHashVerified(ctx, asset.ID, true, size); err != nil {
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
