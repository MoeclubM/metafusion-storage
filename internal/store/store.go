package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	// 空导入只为注册 postgres 驱动：漏掉它时 sql.Open("postgres", …) 会直接报 unknown driver，
	// 而编译与静态检查都发现不了。driver_test.go 专门守住这条。
	_ "github.com/lib/pq"
)

// ErrNotFound 表示目标记录不存在（调用方据此回 404，不区分权限与不存在）。
var ErrNotFound = errors.New("not_found")

// schema 是存储服务自有的 storage schema。服务只读写自己的表，
// 不 JOIN 目录库；实体可见性一律通过 catalog 的 HTTP 契约询问。
// 版本化迁移待补：当前用幂等 DDL 建表，与主仓库 modules 包的做法一致。
const schema = `CREATE SCHEMA IF NOT EXISTS storage;
CREATE TABLE IF NOT EXISTS storage.assets(
  id uuid PRIMARY KEY,
  sha256 text NOT NULL DEFAULT '',
  size_bytes bigint NOT NULL DEFAULT 0,
  declared_size bigint NOT NULL DEFAULT 0,
  mime_type text NOT NULL DEFAULT 'application/octet-stream',
  file_name text NOT NULL,
  object_key text NOT NULL,
  status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','complete')),
  multipart_upload_id text NOT NULL DEFAULT '',
  hash_verified boolean NOT NULL DEFAULT false,
  uploader_id uuid NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  completed_at timestamptz
);
-- 内容寻址：同名内容只登记一次。pending 行的 sha256 先占位，重复提交即续传。
CREATE UNIQUE INDEX IF NOT EXISTS assets_sha256 ON storage.assets(sha256) WHERE sha256 <> '';
CREATE TABLE IF NOT EXISTS storage.bindings(
  id uuid PRIMARY KEY,
  asset_id uuid NOT NULL REFERENCES storage.assets(id) ON DELETE CASCADE,
  target_entity_id uuid NOT NULL,
  target_kind text NOT NULL DEFAULT '',
  binding_role text NOT NULL DEFAULT 'master_archive',
  created_by uuid NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE(asset_id,target_entity_id,binding_role)
);
CREATE INDEX IF NOT EXISTS bindings_entity ON storage.bindings(target_entity_id, created_at DESC);
CREATE INDEX IF NOT EXISTS bindings_asset ON storage.bindings(asset_id);
`

// Asset 是一份物理文件的内容寻址记录：身份是 sha256，不含任何目录语义。
type Asset struct {
	ID                string     `json:"id"`
	SHA256            string     `json:"sha256"`
	SizeBytes         int64      `json:"size_bytes"`
	DeclaredSize      int64      `json:"declared_size"`
	MimeType          string     `json:"mime_type"`
	FileName          string     `json:"file_name"`
	ObjectKey         string     `json:"object_key"`
	Status            string     `json:"status"`
	MultipartUploadID string     `json:"multipart_upload_id,omitempty"`
	HashVerified      bool       `json:"hash_verified"`
	UploaderID        string     `json:"uploader_id"`
	CreatedAt         time.Time  `json:"created_at"`
	CompletedAt       *time.Time `json:"completed_at,omitempty"`
}

// Binding 是"文件 → 目录实体"的挂载：用途用 binding_role 表达（track_audio、disc_image…），
// 位置/区间属于目录侧的 locator，不在这里重复。
type Binding struct {
	ID             string    `json:"id"`
	AssetID        string    `json:"asset_id"`
	TargetEntityID string    `json:"target_entity_id"`
	TargetKind     string    `json:"target_kind"`
	BindingRole    string    `json:"binding_role"`
	CreatedBy      string    `json:"created_by"`
	CreatedAt      time.Time `json:"created_at"`
}

// FileBinding 是列表视图：绑定 + 它指向的文件元数据。
type FileBinding struct {
	Binding
	Asset Asset `json:"asset"`
}

type Store struct{ db *sql.DB }

func Open(ctx context.Context, dsn string) (*Store, error) {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(10)
	if err = db.PingContext(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

// DB 暴露底层连接，供健康检查使用。
func (s *Store) DB() *sql.DB { return s.db }

func (s *Store) Init(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, schema)
	return err
}

const assetCols = "id,sha256,size_bytes,declared_size,mime_type,file_name,object_key,status,multipart_upload_id,hash_verified,uploader_id,created_at,completed_at"

func scanAsset(row interface{ Scan(...any) error }) (Asset, error) {
	var a Asset
	err := row.Scan(&a.ID, &a.SHA256, &a.SizeBytes, &a.DeclaredSize, &a.MimeType, &a.FileName, &a.ObjectKey, &a.Status, &a.MultipartUploadID, &a.HashVerified, &a.UploaderID, &a.CreatedAt, &a.CompletedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Asset{}, ErrNotFound
	}
	return a, err
}

func (s *Store) Asset(ctx context.Context, id string) (Asset, error) {
	return scanAsset(s.db.QueryRowContext(ctx, "SELECT "+assetCols+" FROM storage.assets WHERE id=$1", id))
}

func (s *Store) AssetByHash(ctx context.Context, sha256 string) (Asset, error) {
	return scanAsset(s.db.QueryRowContext(ctx, "SELECT "+assetCols+" FROM storage.assets WHERE sha256=$1", sha256))
}

func (s *Store) CreateAsset(ctx context.Context, a Asset) error {
	_, err := s.db.ExecContext(ctx, "INSERT INTO storage.assets(id,sha256,size_bytes,declared_size,mime_type,file_name,object_key,status,multipart_upload_id,uploader_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
		a.ID, a.SHA256, a.SizeBytes, a.DeclaredSize, a.MimeType, a.FileName, a.ObjectKey, a.Status, a.MultipartUploadID, a.UploaderID)
	return err
}

// SetUploadSession 记录分片上传会话，便于中断后续传复用同一个 uploadID。
func (s *Store) SetUploadSession(ctx context.Context, id, uploadID string) error {
	_, err := s.db.ExecContext(ctx, "UPDATE storage.assets SET multipart_upload_id=$2 WHERE id=$1", id, uploadID)
	return err
}

// CompleteAsset 落定文件大小与完成状态；declaredSize 为 0 时不覆盖（本地对象模式回填）。
func (s *Store) CompleteAsset(ctx context.Context, id string, size int64) error {
	_, err := s.db.ExecContext(ctx, "UPDATE storage.assets SET status='complete', size_bytes=$2, completed_at=now() WHERE id=$1", id, size)
	return err
}

// MarkHashVerified 记录服务端实际读回字节算出的 sha256 是否与声明一致。
func (s *Store) MarkHashVerified(ctx context.Context, id string, verified bool, size int64) error {
	_, err := s.db.ExecContext(ctx, "UPDATE storage.assets SET hash_verified=$2, size_bytes=$3 WHERE id=$1", id, verified, size)
	return err
}

func (s *Store) Bind(ctx context.Context, b Binding) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO storage.bindings(id,asset_id,target_entity_id,target_kind,binding_role,created_by)
		VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(asset_id,target_entity_id,binding_role) DO NOTHING`,
		b.ID, b.AssetID, b.TargetEntityID, b.TargetKind, b.BindingRole, b.CreatedBy)
	return err
}

func (s *Store) Binding(ctx context.Context, id string) (Binding, error) {
	var b Binding
	err := s.db.QueryRowContext(ctx, "SELECT id,asset_id,target_entity_id,target_kind,binding_role,created_by,created_at FROM storage.bindings WHERE id=$1", id).
		Scan(&b.ID, &b.AssetID, &b.TargetEntityID, &b.TargetKind, &b.BindingRole, &b.CreatedBy, &b.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Binding{}, ErrNotFound
	}
	return b, err
}

func (s *Store) Unbind(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, "DELETE FROM storage.bindings WHERE id=$1", id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// BindingsForEntity 列出挂在某个实体上的全部文件；调用方需先确认实体对请求者可见。
func (s *Store) BindingsForEntity(ctx context.Context, entityID string) ([]FileBinding, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT b.id,b.asset_id,b.target_entity_id,b.target_kind,b.binding_role,b.created_by,b.created_at,
		a.id,a.sha256,a.size_bytes,a.declared_size,a.mime_type,a.file_name,a.object_key,a.status,a.multipart_upload_id,a.hash_verified,a.uploader_id,a.created_at,a.completed_at
		FROM storage.bindings b JOIN storage.assets a ON a.id=b.asset_id
		WHERE b.target_entity_id=$1 ORDER BY b.created_at DESC LIMIT 500`, entityID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []FileBinding{}
	for rows.Next() {
		var f FileBinding
		if err = rows.Scan(&f.ID, &f.AssetID, &f.TargetEntityID, &f.TargetKind, &f.BindingRole, &f.CreatedBy, &f.CreatedAt,
			&f.Asset.ID, &f.Asset.SHA256, &f.Asset.SizeBytes, &f.Asset.DeclaredSize, &f.Asset.MimeType, &f.Asset.FileName, &f.Asset.ObjectKey,
			&f.Asset.Status, &f.Asset.MultipartUploadID, &f.Asset.HashVerified, &f.Asset.UploaderID, &f.Asset.CreatedAt, &f.Asset.CompletedAt); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// BindingsForAsset 用于读取鉴权：任一绑定目标可见即可读。
func (s *Store) BindingsForAsset(ctx context.Context, assetID string) ([]Binding, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT id,asset_id,target_entity_id,target_kind,binding_role,created_by,created_at FROM storage.bindings WHERE asset_id=$1", assetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Binding{}
	for rows.Next() {
		var b Binding
		if err = rows.Scan(&b.ID, &b.AssetID, &b.TargetEntityID, &b.TargetKind, &b.BindingRole, &b.CreatedBy, &b.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// Stats 供运营后台查看容量占用。
func (s *Store) Stats(ctx context.Context) (assets int64, bytes int64, err error) {
	err = s.db.QueryRowContext(ctx, "SELECT count(*),COALESCE(sum(size_bytes),0) FROM storage.assets WHERE status='complete'").Scan(&assets, &bytes)
	return assets, bytes, err
}
