-- 000004_reclaim：清理认领令牌（事务条件认领的持有标记）+ 配额预留的锁序基础。
--
-- 与 000001/000003 同一写法：每条语句幂等，启动重复执行不改结构、不报错。
-- reclaim_token 为空表示无人认领；非空 + reclaim_claimed_at 为认领持有，超时未落定
-- 可被后来者接管（进程中断恢复），见 internal/store/reclaim.go。
ALTER TABLE storage.assets ADD COLUMN IF NOT EXISTS reclaim_token text NOT NULL DEFAULT '';
ALTER TABLE storage.assets ADD COLUMN IF NOT EXISTS reclaim_claimed_at timestamptz;
CREATE INDEX IF NOT EXISTS assets_reclaim_claim ON storage.assets(reclaim_claimed_at) WHERE status = 'pending';
