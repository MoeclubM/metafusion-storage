package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/MoeclubM/metafusion-storage/internal/config"
	"github.com/MoeclubM/metafusion-storage/internal/objects"
	"github.com/MoeclubM/metafusion-storage/internal/testutil"
)

// 需要真实 PostgreSQL 的回归：内容寻址登记 → 完成 → 绑定 → 解绑，以及本地对象模式的
// 写入/哈希回读。未设置 STORAGE_TEST_DSN 时整体跳过（测试库会被清理 storage.* 两张表）。
func TestAssetLifecycleAndLocalObjects(t *testing.T) {
	dsn := testutil.DSN(t)
	db := testutil.Database(t)
	ctx := context.Background()

	s, err := Open(ctx, dsn)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer s.Close()
	if err = s.Init(ctx); err != nil {
		t.Fatalf("init schema: %v", err)
	}
	// 先删子表再删母表：绑定对 assets 有外键。
	if _, err = db.ExecContext(ctx, "DELETE FROM storage.bindings"); err != nil {
		t.Fatalf("clean bindings: %v", err)
	}
	if _, err = db.ExecContext(ctx, "DELETE FROM storage.assets"); err != nil {
		t.Fatalf("clean assets: %v", err)
	}

	// 本地对象模式：无需 S3 也能验证写入与哈希回读两条路径。
	objs, err := objects.New(ctx, config.Config{Root: t.TempDir(), S3Bucket: "test", PresignTTL: time.Minute})
	if err != nil {
		t.Fatalf("objects: %v", err)
	}
	if !objs.Local() {
		t.Fatal("未配置 S3 端点时应为本地对象模式")
	}
	content := "hello storage"
	sum := sha256.Sum256([]byte(content))
	digest := hex.EncodeToString(sum[:])
	key := objs.KeyFor(digest, "track.flac")
	size, got, err := objs.PutStream(ctx, key, strings.NewReader(content), digest)
	if err != nil {
		t.Fatalf("put stream: %v", err)
	}
	if got != digest || size != int64(len(content)) {
		t.Fatalf("写入摘要/长度不符: %s(%d) 期望 %s(%d)", got, size, digest, len(content))
	}
	again, hashed, err := objs.HashOf(ctx, key)
	if err != nil || again != digest || hashed != size {
		t.Fatalf("回读校验失败: %s(%d) err=%v", again, hashed, err)
	}

	const uploader = "77777777-7777-7777-7777-777777777777"
	const entity = "88888888-8888-8888-8888-888888888888"
	asset := Asset{
		ID:           uuid.NewString(),
		SHA256:       digest,
		DeclaredSize: size,
		MimeType:     "audio/flac",
		FileName:     "track.flac",
		ObjectKey:    key,
		Status:       "pending",
		UploaderID:   uploader,
	}
	if err = s.CreateAsset(ctx, asset); err != nil {
		t.Fatalf("create asset: %v", err)
	}
	dup := asset
	dup.ID = uuid.NewString()
	if err = s.CreateAsset(ctx, dup); err == nil {
		t.Fatal("同一 sha256 不得登记两次（内容寻址）")
	}
	if loaded, err := s.AssetByHash(ctx, digest); err != nil || loaded.ID != asset.ID || loaded.Status != "pending" {
		t.Fatalf("按哈希读取失败: %+v err=%v", loaded, err)
	}
	// 续传：记录分片会话后完成上传。
	uploadID := "upload-session-1"
	if err = s.SetUploadSession(ctx, asset.ID, uploadID); err != nil {
		t.Fatalf("set upload session: %v", err)
	}
	if loaded, err := s.Asset(ctx, asset.ID); err != nil || loaded.MultipartUploadID != uploadID {
		t.Fatalf("分片会话未落库: %+v err=%v", loaded, err)
	}
	if err = s.CompleteAsset(ctx, asset.ID, size); err != nil {
		t.Fatalf("complete asset: %v", err)
	}
	if err = s.MarkHashVerified(ctx, asset.ID, true, size); err != nil {
		t.Fatalf("mark verified: %v", err)
	}
	if loaded, err := s.Asset(ctx, asset.ID); err != nil || loaded.Status != "complete" || !loaded.HashVerified {
		t.Fatalf("完成态不符: %+v err=%v", loaded, err)
	}

	// 绑定：用途 + 目标实体；重复绑定不产生第二条（同一三元组唯一）。
	binding := Binding{ID: uuid.NewString(), AssetID: asset.ID, TargetEntityID: entity, TargetKind: "track", BindingRole: "track_audio", CreatedBy: uploader}
	if err = s.Bind(ctx, binding); err != nil {
		t.Fatalf("bind: %v", err)
	}
	if err = s.Bind(ctx, binding); err != nil {
		t.Fatalf("重复绑定不应报错: %v", err)
	}
	files, err := s.BindingsForEntity(ctx, entity)
	if err != nil || len(files) != 1 {
		t.Fatalf("实体文件列表 = %d 条, err=%v", len(files), err)
	}
	if files[0].BindingRole != "track_audio" || files[0].Asset.SHA256 != digest {
		t.Fatalf("绑定/文件字段不符: %+v", files[0])
	}
	byAsset, err := s.BindingsForAsset(ctx, asset.ID)
	if err != nil || len(byAsset) != 1 {
		t.Fatalf("文件绑定列表 = %d 条, err=%v", len(byAsset), err)
	}

	// 解绑纠错：删掉后可再删一次应返回 not_found。
	if err = s.Unbind(ctx, binding.ID); err != nil {
		t.Fatalf("unbind: %v", err)
	}
	if err = s.Unbind(ctx, binding.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("重复解绑应返回 not_found，实际 %v", err)
	}

	// 统计：完成态文件数与占用。
	assets, bytes, err := s.Stats(ctx)
	if err != nil || assets < 1 || bytes < size {
		t.Fatalf("统计不符: assets=%d bytes=%d err=%v", assets, bytes, err)
	}
}
