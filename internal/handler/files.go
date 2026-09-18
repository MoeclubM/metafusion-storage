package handler

import (
	"errors"
	"io"
	"mime"
	"net/http"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/MoeclubM/metafusion-storage/internal/auth"
	"github.com/MoeclubM/metafusion-storage/internal/store"
)

// maxBindingProbe 限制一次读取鉴权最多问目录服务几次：绑定是"文件属于谁"的少量元数据，
// 异常多的绑定不值得为一次下载打穿目录服务。
const maxBindingProbe = 20

// contentCacheSeconds 是内联分发的浏览器缓存时长。可见性按**请求**判定（绑定目标是否可见），
// 因此响应只能进私有缓存：共享缓存会把一次成功鉴权的响应复用给无权者。
const contentCacheSeconds = 300

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

// assetContent 按请求鉴权后**原样**把对象内容发给调用者：不转码、不裁剪、不改一个字节。
//
// 与 download 的分工是"稳定地址"与"一次性取件"：download 在对象存储模式下只回一个预签名地址，
// 它的有效期受 STORAGE_PRESIGN_TTL_MINUTES 限制，签名 Host 又是对象存储端点（未配置
// STORAGE_S3_PUBLIC_ENDPOINT 时浏览器根本不可达）；目录里 pictures[].url 这类需要长期可引用、
// 且要能被 <img> 直接加载的地址，只能由本服务每次重新鉴权后转发原档。
// 可见性判定与 download 完全同一处（readable），不可读一律 404，不区分"无权限"与"不存在"。
func (h *Handler) assetContent(c *gin.Context) {
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
	if !h.readable(c, asset) || asset.Status != "complete" {
		fail(c, 404, "not_found")
		return
	}
	obj, size, err := h.objects.Open(ctx, asset.ObjectKey)
	if err != nil {
		fail(c, 503, "storage_unavailable")
		return
	}
	defer obj.Close()
	// 类型与 disposition 都由服务端判定，不看调用方声明的用途：
	//  1. 判定必须落在**最终下发的类型**上（登记值可能被扩展名或内容嗅探覆盖，见 inlineMime），
	//     否则"声明 application/octet-stream、内容是 HTML"就能绕过白名单；
	//  2. 白名单内（位图/音视频/纯文本/PDF 等）才 inline，其余一律 attachment —— 包括
	//     text/html、image/svg+xml、application/xhtml+xml 这些会被当文档渲染的类型（审计 S-3）；
	//  3. nosniff 对所有响应都发：白名单内的 text/plain 也不许浏览器嗅探成 HTML。
	mimeType := inlineMime(asset, obj)
	c.Header("Content-Type", mimeType)
	c.Header("X-Content-Type-Options", "nosniff")
	if inlineAllowed(mimeType) {
		c.Header("Content-Disposition", "inline")
	} else {
		// 附件分支保留真实类型：下载到本地后系统仍能正确识别，收口靠 disposition + nosniff。
		c.Header("Content-Disposition", contentDisposition(asset.FileName))
	}
	c.Header("Cache-Control", "private, max-age="+strconv.Itoa(contentCacheSeconds))
	// 交给 ServeContent：Range 与 If-Modified-Since 由它处理，大文件不用整份读进内存。
	http.ServeContent(c.Writer, c.Request, asset.FileName, time.Time{}, obj)
	_ = size
}

// inlineMime 决定内联响应的内容类型：优先资产登记的 mime（上传时的 mime_type），
// 缺失或退化成 application/octet-stream 时按扩展名、再按内容嗅探补齐。
// 类型不对不会让请求失败，只会让浏览器按"用途不符"拒绝渲染（<img> 拿到 text/plain 就是破图），
// 因此这条兜底必须存在，而不是把 application/octet-stream 直接发出去。
func inlineMime(asset store.Asset, obj io.ReadSeeker) string {
	if m := strings.TrimSpace(asset.MimeType); m != "" && !strings.EqualFold(m, "application/octet-stream") {
		return m
	}
	if ext := path.Ext(asset.FileName); ext != "" {
		if m := mime.TypeByExtension(ext); m != "" {
			return m
		}
	}
	head := make([]byte, 512)
	n, _ := obj.Read(head)
	// 嗅探读走了开头，必须回到起点：剩下的内容由 ServeContent 从当前位置继续发。
	if _, err := obj.Seek(0, io.SeekStart); err != nil {
		return "application/octet-stream"
	}
	if n <= 0 {
		return "application/octet-stream"
	}
	return http.DetectContentType(head[:n])
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
	// 下载口一直就是 attachment，这里补 nosniff：声明类型与实际内容不符时，
	// 别给浏览器任何"按内容重新判定"的机会（对象存储模式那侧由 S3 直发，加不了头）。
	c.Header("X-Content-Type-Options", "nosniff")
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
	if !body(c, &in) {
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
		// 错误码与鉴权中间件（internal/auth 的 Middleware）同口径：客户端按码分支，
		// 同一语义出现两个码会让前端只认其中一个。
		fail(c, 401, "authentication_required")
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
