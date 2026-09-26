package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// ReclaimClaimTimeout 是清理认领的持有上限：持有者超时未落定视为中断，
// 后来者可接管（认领查询与候选列举都按它判定 staleBefore，口径同一处）。
const ReclaimClaimTimeout = 10 * time.Minute

// quotaSiteLockKey 是全站预算的事务级 advisory lock 键：与迁移锁（740204）不同键，
// 同一事务内只与用户预算锁配合。用户预算锁用 hashtext(uploader_id) 的 32 位变体，
// 与 64 位变体的迁移锁不在同一键空间，不会互串。
const quotaSiteLockKey = 740205

// ErrQuotaExceeded 表示容量预算不足（initiate/complete 按实际口径折成 413）。
var ErrQuotaExceeded = errors.New("quota_exceeded")

// ErrTooManyUploads 表示并发预算不足（折成 429）。
var ErrTooManyUploads = errors.New("too_many_uploads")

// QuotaLimits 是配额预留的输入：零值表示该档不限制（与 quotasEnabled 关断语义一致）。
type QuotaLimits struct {
	UserQuotaBytes int64
	SiteQuotaBytes int64
	UserConcurrent int
	SiteConcurrent int
}

// TryClaimReclaim 按“pending + 未禁发 + 租约已过期 + 无绑定 + 无有效认领”原子认领一行。
// 单条 UPDATE … RETURNING：认领本身就是门禁，成功才返回 claimed=true 与持有令牌的行。
// 远程对象操作一律在认领之外做，终删凭令牌（见 DeleteClaimedAsset），不持长事务。
func (s *Store) TryClaimReclaim(ctx context.Context, id string, now time.Time, token string, staleBefore time.Time) (Asset, bool, error) {
	if token == "" {
		return Asset{}, false, errors.New("reclaim token required")
	}
	a, err := scanAsset(s.db.QueryRowContext(ctx, "UPDATE storage.assets AS a SET reclaim_token=$2, reclaim_claimed_at=$3"+
		" WHERE a.id=$1"+
		" AND a.status='pending' AND NOT a.blocked"+
		" AND a.upload_expires_at <= $4"+
		" AND NOT EXISTS (SELECT 1 FROM storage.bindings b WHERE b.asset_id=a.id)"+
		" AND (a.reclaim_token='' OR a.reclaim_claimed_at IS NULL OR a.reclaim_claimed_at <= $5)"+
		" RETURNING "+assetCols, id, token, now, now, staleBefore))
	if errors.Is(err, ErrNotFound) {
		return Asset{}, false, nil
	}
	if err != nil {
		return Asset{}, false, err
	}
	return a, true, nil
}

// ReleaseReclaimClaim 释放自己持有的认领（失败/跳过路径）：只清自己的令牌，
// 不碰已被接管或主动方清掉的行。进程中断则靠超时接管，不走这里。
func (s *Store) ReleaseReclaimClaim(ctx context.Context, id, token string) error {
	_, err := s.db.ExecContext(ctx, "UPDATE storage.assets SET reclaim_token='', reclaim_claimed_at=NULL WHERE id=$1 AND reclaim_token=$2", id, token)
	return err
}

// DeleteClaimedAsset 凭认领令牌终删资产行：复核“pending + 未禁发 + 租约仍过期 + 无绑定 +
// 令牌一致”后才删。续租/完成会清令牌并改租约/状态，绑定会让 NOT EXISTS 失败——
// 主动方胜出，终删返回 deleted=false，调用方只释放、不重试。
func (s *Store) DeleteClaimedAsset(ctx context.Context, id, token string, now time.Time) (bool, error) {
	if token == "" {
		return false, errors.New("reclaim token required")
	}
	res, err := s.db.ExecContext(ctx, "DELETE FROM storage.assets"+
		" WHERE id=$1 AND reclaim_token=$2"+
		" AND status='pending' AND NOT blocked"+
		" AND upload_expires_at <= $3"+
		" AND NOT EXISTS (SELECT 1 FROM storage.bindings WHERE asset_id=storage.assets.id)",
		id, token, now)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// usageInTx 与 UserUsage 同口径，供配额事务内复用（同一事务 + advisory lock 下重查）。
func usageInTx(ctx context.Context, q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, query string, args ...any) (Usage, error) {
	var u Usage
	err := q.QueryRowContext(ctx, query, args...).Scan(&u.CompleteBytes, &u.PendingBytes, &u.PendingCount)
	return u, err
}

// lockQuotaTx 按“先全站、后用户”的固定顺序加事务级 advisory lock：
// 所有配额事务同一顺序，不因用户不同产生死锁等待环。
func lockQuotaTx(ctx context.Context, tx *sql.Tx, userID string) error {
	if _, err := tx.ExecContext(ctx, "SELECT pg_advisory_xact_lock($1)", quotaSiteLockKey); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "SELECT pg_advisory_xact_lock(hashtext($1))", userID); err != nil {
		return err
	}
	return nil
}

// CreatePendingAsset 在同一事务内做“预算预留 + 占位行插入”：锁序固定，
// 判定用的统计是锁内重查的，INSERT 与预留同命运，并发初始化不再互相超发。
// limits 全零时退化为普通插入（调用方 quotasEnabled 关断时不调这里）。
func (s *Store) CreatePendingAsset(ctx context.Context, a Asset, lim QuotaLimits) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = lockQuotaTx(ctx, tx, a.UploaderID); err != nil {
		return err
	}
	u, err := usageInTx(ctx, tx, "SELECT COALESCE(SUM(size_bytes) FILTER (WHERE status='complete'),0),"+
		"COALESCE(SUM(declared_size) FILTER (WHERE status='pending'),0),"+
		"COALESCE(SUM(CASE WHEN status='pending' THEN 1 ELSE 0 END),0)"+
		" FROM storage.assets WHERE uploader_id=$1", a.UploaderID)
	if err != nil {
		return err
	}
	site, err := usageInTx(ctx, tx, "SELECT COALESCE(SUM(size_bytes) FILTER (WHERE status='complete'),0),"+
		"COALESCE(SUM(declared_size) FILTER (WHERE status='pending'),0),"+
		"COALESCE(SUM(CASE WHEN status='pending' THEN 1 ELSE 0 END),0)"+
		" FROM storage.assets")
	if err != nil {
		return err
	}
	if lim.UserConcurrent > 0 && u.PendingCount >= int64(lim.UserConcurrent) {
		return ErrTooManyUploads
	}
	if lim.SiteConcurrent > 0 && site.PendingCount >= int64(lim.SiteConcurrent) {
		return ErrTooManyUploads
	}
	if lim.UserQuotaBytes > 0 && u.CompleteBytes+u.PendingBytes+a.DeclaredSize > lim.UserQuotaBytes {
		return ErrQuotaExceeded
	}
	if lim.SiteQuotaBytes > 0 && site.CompleteBytes+site.PendingBytes+a.DeclaredSize > lim.SiteQuotaBytes {
		return ErrQuotaExceeded
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO storage.assets(id,sha256,size_bytes,declared_size,mime_type,file_name,object_key,status,multipart_upload_id,uploader_id,upload_expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
		a.ID, a.SHA256, a.SizeBytes, a.DeclaredSize, a.MimeType, a.FileName, a.ObjectKey, a.Status, a.MultipartUploadID, a.UploaderID, a.UploadExpiresAt); err != nil {
		return err
	}
	return tx.Commit()
}

// CheckCompleteCapacity 按实际大小兑现容量预算：落定把 pending 声明换成真实字节，
// 差额（多为未知大小的 0 声明）在锁内重算，不足即 ErrQuotaExceeded，资产保持 pending。
// 并发数只会因落定减少，这里不判。
func (s *Store) CheckCompleteCapacity(ctx context.Context, userID string, declared, actual int64, lim QuotaLimits) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = lockQuotaTx(ctx, tx, userID); err != nil {
		return err
	}
	u, err := usageInTx(ctx, tx, "SELECT COALESCE(SUM(size_bytes) FILTER (WHERE status='complete'),0),"+
		"COALESCE(SUM(declared_size) FILTER (WHERE status='pending'),0),"+
		"COALESCE(SUM(CASE WHEN status='pending' THEN 1 ELSE 0 END),0)"+
		" FROM storage.assets WHERE uploader_id=$1", userID)
	if err != nil {
		return err
	}
	site, err := usageInTx(ctx, tx, "SELECT COALESCE(SUM(size_bytes) FILTER (WHERE status='complete'),0),"+
		"COALESCE(SUM(declared_size) FILTER (WHERE status='pending'),0),"+
		"COALESCE(SUM(CASE WHEN status='pending' THEN 1 ELSE 0 END),0)"+
		" FROM storage.assets")
	if err != nil {
		return err
	}
	if lim.UserQuotaBytes > 0 && u.CompleteBytes+u.PendingBytes-declared+actual > lim.UserQuotaBytes {
		return ErrQuotaExceeded
	}
	if lim.SiteQuotaBytes > 0 && site.CompleteBytes+site.PendingBytes-declared+actual > lim.SiteQuotaBytes {
		return ErrQuotaExceeded
	}
	return tx.Commit()
}
