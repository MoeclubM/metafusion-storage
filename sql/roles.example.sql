-- storage schema 的角色样例（数据层隔离 B4 的准备件，编排尚未启用）。
--
-- 目标：即使各服务共用同一个 PostgreSQL 实例，storage 角色也写不了 catalog / community /
-- auth 里的任何对象——把"独立 schema"从命名约定变成库侧权限边界。
--
-- 用法（需超级用户或库 owner，手工执行一次）：
--   psql "$SUPERUSER_DSN" -v ON_ERROR_STOP=1 -f sql/roles.example.sql
-- 之后把本服务的 DATABASE_URL 换成这个角色、口令换成真实值，代码侧不需要任何改动。
-- 库名默认与 README 的 DB_NAME 一致；换库名时同步改下面两处。

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'metafusion_storage') THEN
    CREATE ROLE metafusion_storage LOGIN PASSWORD 'CHANGE_ME_STORAGE_DB_PASSWORD';
  END IF;
END
$$;

-- 连库与建 schema：首次部署时服务会自己建 storage schema（migrations/000001_init.up.sql），
-- 因此需要库级 CREATE；schema 若已由运维预建，这条可以不给。
GRANT CONNECT, CREATE ON DATABASE metafusion_db TO metafusion_storage;

-- 本服务的迁移与查询只碰 storage schema（审计表所在的 audit schema 见文件末尾的例外说明）。
GRANT USAGE, CREATE ON SCHEMA storage TO metafusion_storage;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA storage TO metafusion_storage;
GRANT SELECT, USAGE ON ALL SEQUENCES IN SCHEMA storage TO metafusion_storage;
-- 迁移新增的表默认不带权限，所以默认权限也一并授出（服务自己的表自己用）。
ALTER DEFAULT PRIVILEGES IN SCHEMA storage
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO metafusion_storage;

-- 审计表例外：它在跨服务共用的 audit schema 里（契约 docs/architecture/audit-log.md），
-- 谁先启动谁建表，本服务不一定建它——只授 storage schema 会让审计行全部写失败。
-- 只给 USAGE + 本服务需要的 DML（SELECT/INSERT），不给 CREATE：建表靠上面的库级 CREATE。
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = 'audit') THEN
    GRANT USAGE ON SCHEMA audit TO metafusion_storage;
    GRANT SELECT, INSERT ON ALL TABLES IN SCHEMA audit TO metafusion_storage;
    ALTER DEFAULT PRIVILEGES IN SCHEMA audit
      GRANT SELECT, INSERT ON TABLES TO metafusion_storage;
  END IF;
END
$$;

-- 收回其它 schema 的权限：PUBLIC 对新建 schema 默认没有 USAGE，但历史实例可能被手工放过权。
-- 撤掉 USAGE 后即使 schema 内的表有残留授权也访问不到，误写会立刻报 permission denied。
DO $$
DECLARE
  s text;
BEGIN
  FOREACH s IN ARRAY ARRAY['catalog','community','auth'] LOOP
    IF EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = s) THEN
      EXECUTE format('REVOKE ALL ON SCHEMA %I FROM metafusion_storage', s);
    END IF;
  END LOOP;
END
$$;
