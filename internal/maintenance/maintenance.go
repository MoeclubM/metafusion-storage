// Package maintenance 是存储服务的后台任务入口：上传治理的回收与一致性核查。
//
// 以 storage-server worker 子命令运行（见 cmd/server/main.go），默认跑一次就退出，
// 由 cron/systemd timer 按周期触发——worker 只是同一个可执行程序的另一种模式，
// 不是新的业务服务（生产目标 §6：worker 归各域）。
//
// 两条铁律：清理绝不动被绑定的资产；删字节前先隔离标记。
// 任何一步的"不知道"（读失败、键对不上、缺失比例异常）都只上报不动手。
package maintenance

import (
	"context"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/MoeclubM/metafusion-storage/internal/config"
	"github.com/MoeclubM/metafusion-storage/internal/objects"
	"github.com/MoeclubM/metafusion-storage/internal/store"
)

// cleanupBatch / reconcileBatch 是单次 worker 的处理上限：后台批处理按批推进，
// 不是把全表倒进内存。量大时多跑几次，自然收敛。
const (
	cleanupBatch   = 1000
	reconcileBatch = 500
	reportListCap  = 100
	missingAbortN  = 5
)

// CleanupReport 是单次回收的结果：只计数与抽样键，全量明细看日志。
type CleanupReport struct {
	Candidates           int
	Reclaimed            int
	SharedRowsRemoved    int
	ObjectAlreadyMissing int
	SkippedBound         int
	SkippedKeyMismatch   int
	SkippedRevoked       int
	ObjectErrors         int
	RemovedKeys          []string
	MismatchedKeys       []string
}

// RunCleanup 回收过期未完成的上传占位。每行的处置顺序是固定的：
// 1. 原子认领（状态 + 租约版本 + 无绑定 + 无有效认领）：失败即他人已接管或行已转活跃；
// 2. 重查绑定（认领与终删之间可能有人刚绑上）；
// 3. 双向核对之键检查：对象键前缀必须与声明 sha 对上，否则这行指向了别人的字节；
// 4. 查共享引用：仍有其它资产行（含 complete 秒传复用）指着同一键时只删行、不删字节；
// 5. 独占且对象存在才删字节，删完凭令牌删行；对象本就不存在凭令牌只删行。
// 认领与终删都是单条语句的短事务，远程对象操作在两者之间、不包事务。
// 终删复核全部条件：续租/完成会清令牌并改租约/状态，绑定会让无绑定复核失败——
// 主动方胜出，终删返回未删除时记 SkippedRevoked。
// 读失败（Exists/Remove 报错）时释放认领、行与字节都保留——"不知道"不是"可以删"，下次可重试。
func RunCleanup(ctx context.Context, db *store.Store, objs *objects.Store, cfg config.Config) (CleanupReport, error) {
	var rep CleanupReport
	now := time.Now()
	staleBefore := now.Add(-store.ReclaimClaimTimeout)
	candidates, err := db.ReclaimCandidates(ctx, now, staleBefore, cleanupBatch)
	if err != nil {
		return rep, err
	}
	rep.Candidates = len(candidates)
	for _, a := range candidates {
		token := uuid.NewString()
		claimed, ok, cerr := db.TryClaimReclaim(ctx, a.ID, now, token, staleBefore)
		if cerr != nil {
			rep.ObjectErrors++
			continue
		}
		if !ok {
			// 未认领到：候选列举后行已转活跃（续租/完成/绑定）或被另一 worker 接管。
			rep.SkippedRevoked++
			continue
		}
		release := func() { _ = db.ReleaseReclaimClaim(ctx, claimed.ID, token) }
		bound, err := db.HasBindings(ctx, claimed.ID)
		if err != nil {
			rep.ObjectErrors++
			release()
			continue
		}
		if bound {
			rep.SkippedBound++
			release()
			continue
		}
		if !keyMatchesSHA(claimed.ObjectKey, claimed.SHA256) {
			rep.SkippedKeyMismatch++
			if len(rep.MismatchedKeys) < reportListCap {
				rep.MismatchedKeys = append(rep.MismatchedKeys, claimed.ObjectKey)
			}
			release()
			continue
		}
		refs, err := db.ObjectKeyRefCount(ctx, claimed.ObjectKey)
		if err != nil {
			rep.ObjectErrors++
			release()
			continue
		}
		if refs > 1 {
			// 去重共享：complete 行正复用这份字节，清掉占位行即可，字节是别人的。
			deleted, derr := db.DeleteClaimedAsset(ctx, claimed.ID, token, now)
			if derr != nil {
				rep.ObjectErrors++
				release()
				continue
			}
			if !deleted {
				rep.SkippedRevoked++
				release()
				continue
			}
			rep.SharedRowsRemoved++
			continue
		}
		exists, err := objs.Exists(ctx, claimed.ObjectKey)
		if err != nil {
			rep.ObjectErrors++
			release()
			continue
		}
		if !exists {
			deleted, derr := db.DeleteClaimedAsset(ctx, claimed.ID, token, now)
			if derr != nil {
				rep.ObjectErrors++
				release()
				continue
			}
			if !deleted {
				rep.SkippedRevoked++
				release()
				continue
			}
			rep.ObjectAlreadyMissing++
			continue
		}
		if err := objs.Remove(ctx, claimed.ObjectKey); err != nil {
			rep.ObjectErrors++
			release()
			continue
		}
		deleted, derr := db.DeleteClaimedAsset(ctx, claimed.ID, token, now)
		if derr != nil || !deleted {
			// 字节已删、行还在：行已转活跃（删前瞬间被续租/完成/绑定）或写库失败。
			// complete 行挂着缺失的键由对账标禁发，pending 行下次按缺失键收尾，可观测、可恢复。
			rep.ObjectErrors++
			continue
		}
		rep.Reclaimed++
		if len(rep.RemovedKeys) < reportListCap {
			rep.RemovedKeys = append(rep.RemovedKeys, claimed.ObjectKey)
		}
	}
	return rep, nil
}

// ReconcileReport 是单次对账的结果。
type ReconcileReport struct {
	CheckedComplete    int
	MissingAssetIDs    []string
	MarkedBlocked      int
	MarkingAborted     bool
	ReadErrors         int
	OrphansSeen        int
	OrphansQuarantined int
	QuarantineErrors   int
}

// RunReconcile 双向核对：库→对象（complete 行是否真有字节）与对象→库（无引用的键记孤儿台账）。
// 缺失的 complete 行先禁发标记（隔离），不解绑不删行；孤儿先搬隔离区，不删字节。
// 熔断：读错存在、或缺失比例异常（缺失多且占比过半）时只上报不标记——那更像
// 对象存储整体不可用或桶配错，而不是"这几份内容丢了"，批量禁发会把故障放大成事故。
func RunReconcile(ctx context.Context, db *store.Store, objs *objects.Store, cfg config.Config) (ReconcileReport, error) {
	var rep ReconcileReport
	missing := []store.CompleteKey{}
	for offset := 0; ; offset += reconcileBatch {
		page, err := db.ListCompleteKeys(ctx, reconcileBatch, offset)
		if err != nil {
			return rep, err
		}
		for _, k := range page {
			rep.CheckedComplete++
			exists, err := objs.Exists(ctx, k.ObjectKey)
			if err != nil {
				rep.ReadErrors++
				continue
			}
			if !exists {
				missing = append(missing, k)
				if len(rep.MissingAssetIDs) < reportListCap {
					rep.MissingAssetIDs = append(rep.MissingAssetIDs, k.ID)
				}
			}
		}
		if len(page) < reconcileBatch {
			break
		}
	}
	if shouldMarkMissing(len(missing), rep.CheckedComplete, rep.ReadErrors) {
		for _, k := range missing {
			// 隔离标记：禁发位只拦分发，绑定与元数据原样保留，字节恢复后解禁即回。
			if err := db.SetBlocked(ctx, k.ID, "object_missing"); err != nil {
				rep.ReadErrors++
				continue
			}
			rep.MarkedBlocked++
		}
	} else if len(missing) > 0 {
		rep.MarkingAborted = true
	}
	if err := scanOrphans(ctx, db, objs, cfg, &rep); err != nil {
		return rep, err
	}
	return rep, nil
}

// scanOrphans 做对象→库一半：列出对象键，无引用的记台账；超过保留期仍无引用的搬隔离区。
func scanOrphans(ctx context.Context, db *store.Store, objs *objects.Store, cfg config.Config, rep *ReconcileReport) error {
	keys, err := objs.ListKeys(ctx, "objects/", 0)
	if err != nil {
		return err
	}
	for _, key := range keys {
		ref, err := db.IsKeyReferenced(ctx, key)
		if err != nil {
			rep.ReadErrors++
			continue
		}
		if ref {
			continue
		}
		if err := db.UpsertOrphanSeen(ctx, key, "reconcile"); err != nil {
			rep.ReadErrors++
			continue
		}
		rep.OrphansSeen++
	}
	due, err := db.ListOrphansDue(ctx, time.Now().Add(-cfg.OrphanRetention()), reconcileBatch)
	if err != nil {
		return err
	}
	for _, key := range due {
		// 隔离前最后一查：扫描与搬运之间可能有人刚上传绑定上，台账过期则收尾。
		ref, err := db.IsKeyReferenced(ctx, key)
		if err != nil {
			rep.ReadErrors++
			continue
		}
		if ref {
			_ = db.ClearOrphan(ctx, key)
			continue
		}
		if _, err := objs.Quarantine(ctx, key); err != nil {
			rep.QuarantineErrors++
			continue
		}
		if err := db.MarkOrphanQuarantined(ctx, key); err != nil {
			rep.QuarantineErrors++
			continue
		}
		rep.OrphansQuarantined++
	}
	return nil
}

// pendingExpired 与回收 SQL 一致：缺租约的行不可回收。
func pendingExpired(expiresAt *time.Time, now time.Time) bool {
	return expiresAt != nil && !expiresAt.After(now)
}

// keyMatchesSHA 是双向核对的键检查：对象键必须落在声明 sha 的前缀下。
// 文件名后缀可变（同一内容重传文件名不同），前缀是唯一的身份断言。
func keyMatchesSHA(objectKey, sha256hex string) bool {
	if objectKey == "" || sha256hex == "" {
		return false
	}
	return strings.HasPrefix(objectKey, objects.KeyPrefixFor(sha256hex))
}

// shouldMarkMissing 决定是否把缺失对象标记为禁发（纯函数，便于单测固定口径）：
// 有读错、零检查、缺失多且占比过半时一律不标记——只上报，等人工看。
func shouldMarkMissing(missing, checked, readErrors int) bool {
	if missing == 0 || checked == 0 {
		return false
	}
	if readErrors > 0 {
		return false
	}
	if missing >= missingAbortN && float64(missing)/float64(checked) > 0.5 {
		return false
	}
	return true
}
