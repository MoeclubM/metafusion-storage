package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/MoeclubM/metafusion-storage/internal/testutil"
)

func reclaimTestStore(t *testing.T) (*Store, context.Context) {
	t.Helper()
	dsn := testutil.DSN(t)
	db := testutil.Database(t)
	s, err := Open(context.Background(), dsn)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	ctx := context.Background()
	if err = s.Init(ctx); err != nil {
		t.Fatalf("init schema: %v", err)
	}
	if _, err = db.ExecContext(ctx, "DELETE FROM storage.bindings"); err != nil {
		t.Fatalf("clean bindings: %v", err)
	}
	if _, err = db.ExecContext(ctx, "DELETE FROM storage.assets"); err != nil {
		t.Fatalf("clean assets: %v", err)
	}
	return s, ctx
}

func reclaimAsset(expired time.Time, uploader string) Asset {
	sum := sha256.Sum256([]byte(uuid.NewString()))
	digest := hex.EncodeToString(sum[:])
	return Asset{
		ID:              uuid.NewString(),
		SHA256:          digest,
		DeclaredSize:    10,
		MimeType:        "application/octet-stream",
		FileName:        "f.bin",
		ObjectKey:       "objects/" + digest[:2] + "/" + digest + "/f.bin",
		Status:          "pending",
		UploaderID:      uploader,
		UploadExpiresAt: &expired,
	}
}

// 双 worker 同时认领同一行：恰好一个持有者，另一个看到未认领（无认领边界即双删）。
func TestReclaimClaimMutualExclusion(t *testing.T) {
	s, ctx := reclaimTestStore(t)
	now := time.Now()
	a := reclaimAsset(now.Add(-time.Hour), "11111111-1111-1111-1111-111111111111")
	if err := s.CreateAsset(ctx, a); err != nil {
		t.Fatalf("create: %v", err)
	}
	stale := now.Add(-ReclaimClaimTimeout)
	legacy := now.Add(-72 * time.Hour)
	var wg sync.WaitGroup
	got := make([]bool, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, ok, err := s.TryClaimReclaim(ctx, a.ID, now, legacy, uuid.NewString(), stale)
			if err != nil {
				t.Errorf("claim %d: %v", i, err)
				return
			}
			got[i] = ok
		}(i)
	}
	wg.Wait()
	if (got[0] && got[1]) || (!got[0] && !got[1]) {
		t.Fatalf("双认领必须恰好一个成功，实际 %v", got)
	}
}

// 持有超时未落定视为中断：后来者可接管（进程中断恢复），未超时则不可抢占。
func TestReclaimClaimStaleTakeover(t *testing.T) {
	s, ctx := reclaimTestStore(t)
	now := time.Now()
	a := reclaimAsset(now.Add(-time.Hour), "11111111-1111-1111-1111-111111111111")
	if err := s.CreateAsset(ctx, a); err != nil {
		t.Fatalf("create: %v", err)
	}
	stale := now.Add(-ReclaimClaimTimeout)
	legacy := now.Add(-72 * time.Hour)
	if _, ok, err := s.TryClaimReclaim(ctx, a.ID, now, legacy, "holder-1", stale); err != nil || !ok {
		t.Fatalf("首次认领应成功 ok=%v err=%v", ok, err)
	}
	if _, ok, err := s.TryClaimReclaim(ctx, a.ID, now, legacy, "holder-2", stale); err != nil || ok {
		t.Fatalf("有效认领不可抢占 ok=%v err=%v", ok, err)
	}
	db := testutil.Database(t)
	if _, err := db.ExecContext(ctx, "UPDATE storage.assets SET reclaim_claimed_at = now() - interval '1 hour' WHERE id=$1", a.ID); err != nil {
		t.Fatalf("backdate: %v", err)
	}
	if _, ok, err := s.TryClaimReclaim(ctx, a.ID, now, legacy, "holder-2", stale); err != nil || !ok {
		t.Fatalf("超时认领应可接管 ok=%v err=%v", ok, err)
	}
}

// 终删是条件删除：续租/完成/绑定任一发生后，旧令牌删不动行（主动方胜出）。
func TestDeleteClaimedAssetRevokedByActiveOps(t *testing.T) {
	renew := func(t *testing.T, s *Store, ctx context.Context, a Asset) {
		if err := s.SetUploadExpiry(ctx, a.ID, time.Now().Add(time.Hour)); err != nil {
			t.Fatalf("renew: %v", err)
		}
	}
	complete := func(t *testing.T, s *Store, ctx context.Context, a Asset) {
		if err := s.MarkHashVerified(ctx, a.ID, 10); err != nil {
			t.Fatalf("verify: %v", err)
		}
		if err := s.CompleteAsset(ctx, a.ID, 10); err != nil {
			t.Fatalf("complete: %v", err)
		}
	}
	bind := func(t *testing.T, s *Store, ctx context.Context, a Asset) {
		if err := s.Bind(ctx, Binding{ID: uuid.NewString(), AssetID: a.ID,
			TargetEntityID: "22222222-2222-2222-2222-222222222222", TargetKind: "track",
			BindingRole: "track_audio", CreatedBy: a.UploaderID}); err != nil {
			t.Fatalf("bind: %v", err)
		}
	}
	for name, op := range map[string]func(*testing.T, *Store, context.Context, Asset){
		"renew": renew, "complete": complete, "bind": bind,
	} {
		t.Run(name, func(t *testing.T) {
			s, ctx := reclaimTestStore(t)
			now := time.Now()
			a := reclaimAsset(now.Add(-time.Hour), "11111111-1111-1111-1111-111111111111")
			if err := s.CreateAsset(ctx, a); err != nil {
				t.Fatalf("create: %v", err)
			}
			stale := now.Add(-ReclaimClaimTimeout)
			legacy := now.Add(-72 * time.Hour)
			if _, ok, err := s.TryClaimReclaim(ctx, a.ID, now, legacy, "stale-holder", stale); err != nil || !ok {
				t.Fatalf("认领应成功 ok=%v err=%v", ok, err)
			}
			op(t, s, ctx, a)
			if deleted, err := s.DeleteClaimedAsset(ctx, a.ID, "stale-holder", now, legacy); err != nil || deleted {
				t.Fatalf("主动操作后旧令牌不得删行 deleted=%v err=%v", deleted, err)
			}
			if _, err := s.Asset(ctx, a.ID); err != nil {
				t.Fatalf("活跃资产行必须保留: %v", err)
			}
		})
	}
}

// 并发初始化在同一事务内串行化：配额只够一份时恰好一份成功，其余配额不足。
func TestCreatePendingAssetConcurrentQuota(t *testing.T) {
	s, ctx := reclaimTestStore(t)
	mb := int64(1) << 20
	lim := QuotaLimits{UserQuotaBytes: mb, UserConcurrent: 100}
	uploader := "33333333-3333-3333-3333-333333333333"
	const n = 5
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			sum := sha256.Sum256([]byte(fmt.Sprintf("racer-%d-%s", i, uuid.NewString())))
			digest := hex.EncodeToString(sum[:])
			lease := time.Now().Add(time.Hour)
			errs[i] = s.CreatePendingAsset(ctx, Asset{
				ID: uuid.NewString(), SHA256: digest, DeclaredSize: mb,
				MimeType: "application/octet-stream", FileName: "r.bin",
				ObjectKey: "objects/" + digest[:2] + "/" + digest + "/r.bin",
				Status: "pending", UploaderID: uploader, UploadExpiresAt: &lease,
			}, lim)
		}(i)
	}
	wg.Wait()
	ok, over := 0, 0
	for _, err := range errs {
		switch {
		case err == nil:
			ok++
		case errors.Is(err, ErrQuotaExceeded):
			over++
		default:
			t.Fatalf("意外的预留错误: %v", err)
		}
	}
	if ok != 1 || over != n-1 {
		t.Fatalf("配额只够一份时应恰好一份成功，实际成功=%d 超限=%d", ok, over)
	}
}

// 完成按实际大小兑现：未知大小（0 声明）的落定在锁内重算，不足即超限。
func TestCheckCompleteCapacityRedeem(t *testing.T) {
	s, ctx := reclaimTestStore(t)
	mb := int64(1) << 20
	lim := QuotaLimits{UserQuotaBytes: mb}
	uploader := "44444444-4444-4444-4444-444444444444"
	lease := time.Now().Add(time.Hour)
	sum := sha256.Sum256([]byte("filler" + uuid.NewString()))
	fillerSHA := hex.EncodeToString(sum[:])
	if err := s.CreateAsset(ctx, Asset{
		ID: uuid.NewString(), SHA256: fillerSHA, DeclaredSize: mb - 10,
		MimeType: "application/octet-stream", FileName: "fill.bin",
		ObjectKey: "objects/" + fillerSHA[:2] + "/" + fillerSHA + "/fill.bin",
		Status: "pending", UploaderID: uploader, UploadExpiresAt: &lease,
	}); err != nil {
		t.Fatalf("filler: %v", err)
	}
	if err := s.CheckCompleteCapacity(ctx, uploader, 0, 10, lim); err != nil {
		t.Fatalf("恰好填满应通过: %v", err)
	}
	if err := s.CheckCompleteCapacity(ctx, uploader, 0, 11, lim); !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("超出 1 字节应超限，实际 %v", err)
	}
}
