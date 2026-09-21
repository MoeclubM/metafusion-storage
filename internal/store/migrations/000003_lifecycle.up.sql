-- 000003_lifecycle：上传治理（租约）+ 禁发分离 + 一致性核查的列与表。
--
-- 与 000001 同一写法：每条语句幂等（ADD COLUMN IF NOT EXISTS / IF NOT EXISTS），
-- 启动重复执行不改结构、不报错；查询侧在 internal/store/lifecycle.go，列集合变更
-- 同步核对 store.go 的 assetCols 与扫描顺序。
--
-- 设计说明（生产目标 §6 三态：校验完成 status / 目录公开 catalog / 允许分发 blocked）：
-- 禁发用独立列 blocked 而不是第三个 status 值：status 只回答"内容是否验过"，
-- blocked 只回答"是否允许分发"，解禁后原状态仍在，不需要"解禁恢复"分支。

-- 上传租约：initiate 落定到期时间，过期未完成的 pending 由后台清理任务回收。
-- 存量行（升级前已存在的 pending）为 NULL：清理查询把 NULL 按 created_at + 默认
-- TTL 兜底，不在这里回填策略值——迁移只给结构，不写治理参数。
ALTER TABLE storage.assets ADD COLUMN IF NOT EXISTS upload_expires_at timestamptz;
-- 禁发标记：blocked=true 的资产不可分发（下载/预览/签名/列表统一门禁），
-- 与 status 正交；blocked_at/blocked_reason 只做处置留痕，不参与判定。
ALTER TABLE storage.assets ADD COLUMN IF NOT EXISTS blocked boolean NOT NULL DEFAULT false;
ALTER TABLE storage.assets ADD COLUMN IF NOT EXISTS blocked_reason text NOT NULL DEFAULT '';
ALTER TABLE storage.assets ADD COLUMN IF NOT EXISTS blocked_at timestamptz;

-- 过期 pending 扫描：只命中"未完成、无绑定、已过期"的行（清理任务入口见 maintenance）。
CREATE INDEX IF NOT EXISTS assets_pending_expiry ON storage.assets(upload_expires_at) WHERE status = 'pending';
-- 被禁发资产的运营盘点。
CREATE INDEX IF NOT EXISTS assets_blocked ON storage.assets(blocked_at) WHERE blocked;
-- 按上传者的配额统计（容量/并发）：complete 计 size_bytes，pending 计 declared_size。
CREATE INDEX IF NOT EXISTS assets_uploader ON storage.assets(uploader_id, status);

-- 孤儿对象台账：对象存储上有、库里没有任何资产引用的键。
-- 流程是"先隔离标记再删"：first_seen_at 记录首次发现，保留期过后由 worker 搬进
-- quarantine/ 前缀并写 quarantined_at；真正的字节删除由运维确认，worker 不自动删。
CREATE TABLE IF NOT EXISTS storage.orphaned_objects(
  object_key text PRIMARY KEY,
  first_seen_at timestamptz NOT NULL DEFAULT now(),
  quarantined_at timestamptz,
  note text NOT NULL DEFAULT ''
);
