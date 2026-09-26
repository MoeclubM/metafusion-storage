-- 旧 pending 行没有租约时，按历史默认的 72 小时窗口写入明确的到期时间。
-- 后续回收仅依据 upload_expires_at，不再查询 created_at 兼容分支。
UPDATE storage.assets
   SET upload_expires_at = created_at + interval '72 hours'
 WHERE status = 'pending' AND upload_expires_at IS NULL;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'assets_pending_requires_expiry'
                 AND conrelid = 'storage.assets'::regclass) THEN
    ALTER TABLE storage.assets ADD CONSTRAINT assets_pending_requires_expiry
      CHECK (status <> 'pending' OR upload_expires_at IS NOT NULL);
  END IF;
END $$;
