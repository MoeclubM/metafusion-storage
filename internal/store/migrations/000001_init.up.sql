-- 000001_init：storage schema 的基线结构，本服务表结构的唯一来源。
--
-- 与 internal/store 的查询逐列对应：assetCols 的列顺序、各 INSERT/SELECT 的列集合
-- 都按这里写；改这个文件等于改生产结构，必须同时核对代码与 internal/store 的冻结用例。
--
-- 每条语句都必须幂等（IF NOT EXISTS / ADD COLUMN IF NOT EXISTS）：启动时执行，
-- 老实例重复启动不能改结构、不能报错。历史实例的结构差异也用幂等语句补齐，
-- 不另写"补丁迁移"——基线本身就是可重复执行的。

CREATE SCHEMA IF NOT EXISTS storage;

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
  -- fail_reason 记下服务端回读校验的失败原因（hash_mismatch / verify_timeout /
  -- hash_verify_too_large）：这些资产会一直留在 pending，不落原因就只剩"没完成"可查。
  fail_reason text NOT NULL DEFAULT '',
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

-- 存量实例补列：CREATE TABLE IF NOT EXISTS 对既有表是空操作，
-- 新增列必须单独写一条幂等 DDL，否则升级后的实例连查询都会因缺列直接失败。
ALTER TABLE storage.assets ADD COLUMN IF NOT EXISTS fail_reason text NOT NULL DEFAULT '';
