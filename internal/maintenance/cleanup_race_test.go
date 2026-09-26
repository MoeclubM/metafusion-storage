package maintenance

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/MoeclubM/metafusion-storage/internal/config"
	"github.com/MoeclubM/metafusion-storage/internal/objects"
	"github.com/MoeclubM/metafusion-storage/internal/store"
	"github.com/MoeclubM/metafusion-storage/internal/testutil"
)

type cleanupFixture struct {
	t    *testing.T
	db   *store.Store
	objs *objects.Store
	root string
	cfg  config.Config
	ctx  context.Context
}

func newCleanupFixture(t *testing.T) *cleanupFixture {
	t.Helper()
	dsn := testutil.DSN(t)
	raw := testutil.Database(t)
	s, err := store.Open(context.Background(), dsn)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	ctx := context.Background()
	if err = s.Init(ctx); err != nil {
		t.Fatalf("init schema: %v", err)
	}
	if _, err = raw.ExecContext(ctx, "DELETE FROM storage.bindings"); err != nil {
		t.Fatalf("clean bindings: %v", err)
	}
	if _, err = raw.ExecContext(ctx, "DELETE FROM storage.assets"); err != nil {
		t.Fatalf("clean assets: %v", err)
	}
	if _, err = raw.ExecContext(ctx, "DELETE FROM storage.orphaned_objects"); err != nil {
		t.Fatalf("clean orphans: %v", err)
	}
	root := t.TempDir()
	objs, err := objects.New(ctx, config.Config{Root: root, S3Bucket: "test", PresignTTL: time.Minute})
	if err != nil {
		t.Fatalf("objects: %v", err)
	}
	cfg := config.Config{PendingTTLHours: 72, UploadLeaseMinutes: 120}
	return &cleanupFixture{t: t, db: s, objs: objs, root: root, cfg: cfg, ctx: ctx}
}

// expiredPending 登记一份租约已过期的 pending；withBytes 为真时同步写入对象字节。
func (f *cleanupFixture) expiredPending(content string, withBytes bool) store.Asset {
	f.t.Helper()
	sum := sha256.Sum256([]byte(content + uuid.NewString()))
	digest := hex.EncodeToString(sum[:])
	key := f.objs.KeyFor(digest, "track.bin")
	if withBytes {
		body := content + "-body"
		sum2 := sha256.Sum256([]byte(body))
		d2 := hex.EncodeToString(sum2[:])
		key = f.objs.KeyFor(d2, "track.bin")
		if _, _, err := f.objs.PutStream(f.ctx, key, strings.NewReader(body), d2); err != nil {
			f.t.Fatalf("put: %v", err)
		}
		digest = d2
	}
	expired := time.Now().Add(-time.Hour)
	a := store.Asset{
		ID: uuid.NewString(), SHA256: digest, DeclaredSize: 10,
		MimeType: "application/octet-stream", FileName: "track.bin",
		ObjectKey: key, Status: "pending", UploaderID: "55555555-5555-5555-5555-555555555555",
		UploadExpiresAt: &expired,
	}
	if err := f.db.CreateAsset(f.ctx, a); err != nil {
		f.t.Fatalf("create: %v", err)
	}
	return a
}

func (f *cleanupFixture) mustGet(id string) store.Asset {
	f.t.Helper()
	a, err := f.db.Asset(f.ctx, id)
	if err != nil {
		f.t.Fatalf("行 %s 应保留: %v", id, err)
	}
	return a
}

// 候选列举后、清理执行前分别发生续租/完成/绑定：活跃资产一律不得删。
func TestCleanupSkipsActiveAfterCandidate(t *testing.T) {
	t.Run("renew", func(t *testing.T) {
		f := newCleanupFixture(t)
		a := f.expiredPending("renew", true)
		now := time.Now()
		if _, err := f.db.ReclaimCandidates(f.ctx, now, now.Add(-store.ReclaimClaimTimeout), 100); err != nil {
			t.Fatalf("candidates: %v", err)
		}
		if err := f.db.SetUploadExpiry(f.ctx, a.ID, time.Now().Add(2*time.Hour)); err != nil {
			t.Fatalf("renew: %v", err)
		}
		rep, err := RunCleanup(f.ctx, f.db, f.objs, f.cfg)
		if err != nil {
			t.Fatalf("cleanup: %v", err)
		}
		if rep.Reclaimed != 0 || rep.SharedRowsRemoved != 0 || rep.ObjectAlreadyMissing != 0 {
			t.Fatalf("续租后不得回收任何行: %+v", rep)
		}
		f.mustGet(a.ID)
		if exists, _ := f.objs.Exists(f.ctx, a.ObjectKey); !exists {
			t.Fatal("续租资产的字节不得删")
		}
	})
	t.Run("complete", func(t *testing.T) {
		f := newCleanupFixture(t)
		a := f.expiredPending("complete", true)
		now := time.Now()
		if _, err := f.db.ReclaimCandidates(f.ctx, now, now.Add(-store.ReclaimClaimTimeout), 100); err != nil {
			t.Fatalf("candidates: %v", err)
		}
		if err := f.db.MarkHashVerified(f.ctx, a.ID, 10); err != nil {
			t.Fatalf("verify: %v", err)
		}
		if err := f.db.CompleteAsset(f.ctx, a.ID, 10); err != nil {
			t.Fatalf("complete: %v", err)
		}
		rep, err := RunCleanup(f.ctx, f.db, f.objs, f.cfg)
		if err != nil {
			t.Fatalf("cleanup: %v", err)
		}
		if rep.Reclaimed != 0 || rep.SharedRowsRemoved != 0 || rep.ObjectAlreadyMissing != 0 {
			t.Fatalf("完成后不得回收: %+v", rep)
		}
		got := f.mustGet(a.ID)
		if got.Status != "complete" {
			t.Fatalf("完成态应保留 status=%s", got.Status)
		}
	})
	t.Run("bind", func(t *testing.T) {
		f := newCleanupFixture(t)
		a := f.expiredPending("bind", true)
		now := time.Now()
		if _, err := f.db.ReclaimCandidates(f.ctx, now, now.Add(-store.ReclaimClaimTimeout), 100); err != nil {
			t.Fatalf("candidates: %v", err)
		}
		if err := f.db.Bind(f.ctx, store.Binding{ID: uuid.NewString(), AssetID: a.ID,
			TargetEntityID: "66666666-6666-6666-6666-666666666666", TargetKind: "track",
			BindingRole: "track_audio", CreatedBy: a.UploaderID}); err != nil {
			t.Fatalf("bind: %v", err)
		}
		rep, err := RunCleanup(f.ctx, f.db, f.objs, f.cfg)
		if err != nil {
			t.Fatalf("cleanup: %v", err)
		}
		if rep.Reclaimed != 0 || rep.SharedRowsRemoved != 0 || rep.ObjectAlreadyMissing != 0 {
			t.Fatalf("绑定后不得回收: %+v", rep)
		}
		f.mustGet(a.ID)
		if exists, _ := f.objs.Exists(f.ctx, a.ObjectKey); !exists {
			t.Fatal("已绑定资产的字节不得删")
		}
	})
}

// 双 worker 同时跑：同一行恰好被回收一次，字节与行同命运。
func TestCleanupDualWorker(t *testing.T) {
	f := newCleanupFixture(t)
	a := f.expiredPending("dual", true)
	var wg sync.WaitGroup
	reps := make([]CleanupReport, 2)
	errs := make([]error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			reps[i], errs[i] = RunCleanup(f.ctx, f.db, f.objs, f.cfg)
		}(i)
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			t.Fatalf("cleanup: %v", err)
		}
	}
	if total := reps[0].Reclaimed + reps[1].Reclaimed; total != 1 {
		t.Fatalf("双 worker 应恰好回收一次，实际 %+v", reps)
	}
	if _, err := f.db.Asset(f.ctx, a.ID); err == nil {
		t.Fatal("回收后行应消失")
	}
	if exists, _ := f.objs.Exists(f.ctx, a.ObjectKey); exists {
		t.Fatal("回收后字节应消失")
	}
}

// 对象删除失败可重试：先失败（行与字节保留），修好后下次回收。
func TestCleanupObjectRemoveFailureThenRetry(t *testing.T) {
	f := newCleanupFixture(t)
	a := f.expiredPending("fail", false)
	// 在键路径上放一个非空目录：Exists 为真、Remove 必败（本地模式 os.Remove 删不动非空目录）。
	dir := filepath.Join(f.root, filepath.FromSlash(a.ObjectKey))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "junk"), []byte("junk"), 0o600); err != nil {
		t.Fatalf("junk: %v", err)
	}
	rep, err := RunCleanup(f.ctx, f.db, f.objs, f.cfg)
	if err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if rep.ObjectErrors != 1 || rep.Reclaimed != 0 {
		t.Fatalf("删除失败应记错且不行删: %+v", rep)
	}
	f.mustGet(a.ID)
	// 修好：挪走目录、写入真实字节，下次回收。
	if err := os.RemoveAll(dir); err != nil {
		t.Fatalf("rmdir: %v", err)
	}
	body := "fail-body"
	sum := sha256.Sum256([]byte(body))
	d2 := hex.EncodeToString(sum[:])
	key2 := f.objs.KeyFor(d2, "track.bin")
	if _, _, err := f.objs.PutStream(f.ctx, key2, strings.NewReader(body), d2); err != nil {
		t.Fatalf("put: %v", err)
	}
	raw := testutil.Database(t)
	if _, err := raw.ExecContext(f.ctx, "UPDATE storage.assets SET sha256=$2, object_key=$3 WHERE id=$1", a.ID, d2, key2); err != nil {
		t.Fatalf("repoint: %v", err)
	}
	rep2, err := RunCleanup(f.ctx, f.db, f.objs, f.cfg)
	if err != nil {
		t.Fatalf("cleanup2: %v", err)
	}
	if rep2.Reclaimed != 1 {
		t.Fatalf("修好后应回收: %+v", rep2)
	}
}

// 进程中断恢复：认领后崩溃（不释放不终删），超时后后来者接管并落定。
func TestCleanupCrashRecovery(t *testing.T) {
	f := newCleanupFixture(t)
	a := f.expiredPending("crash", true)
	now := time.Now()
	if _, ok, err := f.db.TryClaimReclaim(f.ctx, a.ID, now, "crashed-holder", now.Add(-store.ReclaimClaimTimeout)); err != nil || !ok {
		t.Fatalf("模拟崩溃前认领应成功 ok=%v err=%v", ok, err)
	}
	raw := testutil.Database(t)
	if _, err := raw.ExecContext(f.ctx, "UPDATE storage.assets SET reclaim_claimed_at = now() - interval '1 hour' WHERE id=$1", a.ID); err != nil {
		t.Fatalf("backdate: %v", err)
	}
	rep, err := RunCleanup(f.ctx, f.db, f.objs, f.cfg)
	if err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if rep.Reclaimed != 1 {
		t.Fatalf("超时认领应被接管并回收: %+v", rep)
	}
	if _, err := f.db.Asset(f.ctx, a.ID); err == nil {
		t.Fatal("回收后行应消失")
	}
}
