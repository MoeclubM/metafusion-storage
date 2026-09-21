# 主仓 compose 变量需求清单（存储最小权限与治理）

只列清单，不动主仓文件。主仓实施时按此修改 `deploy/docker-compose.yml` 的存储注入段。

## 必改（最小权限）

| 变量 | 改成 | 原因 |
| --- | --- | --- |
| `STORAGE_S3_ACCESS_KEY` / `STORAGE_S3_SECRET_KEY` | 仅目标桶的服务用户凭据（策略见本仓 README“对象最小权限”） | 现状是 RustFS root 级凭据；服务只需要目标桶内数据操作 |
| `STORAGE_S3_SKIP_BUCKET_ENSURE` | `true` | 跳过启动建桶检查（服务凭据无建桶能力）；桶由运维身份事先建好 |

运维身份（建桶/删桶/跨桶）走部署期手工或独立任务，不进服务容器环境。

## 可选（按需收敛）

| 变量 | 建议 | 原因 |
| --- | --- | --- |
| `STORAGE_PRESIGN_TTL_MINUTES` | 按禁发时效要求调小（默认 120） | 已签发地址在有效期内拦不住；要求立即禁发的分发用短期签名或鉴权代理 |
| `STORAGE_USER_QUOTA_MB` / `STORAGE_SITE_QUOTA_MB` | 先看 `GET /api/storage/stats` 再定 | 容量预算；超限 `initiate` 回 `413 quota_exceeded` |
| `STORAGE_USER_CONCURRENT_UPLOADS` / `STORAGE_SITE_CONCURRENT_UPLOADS` | 按并发实测定 | 并发预算；超限回 `429 too_many_uploads` |
| `STORAGE_PENDING_TTL_HOURS`（默认 72）/ `STORAGE_ORPHAN_RETENTION_DAYS`（默认 7） | 按磁盘水位调 | 回收与孤儿隔离的节奏 |

## 新增（后台任务触发器，二选一）

- cron 或 systemd timer 周期执行 `storage-server worker`（与服务同一镜像同一环境，跑一次退出）；
- 或在 compose 侧加一次性任务容器复用存储环境变量。

## 不改

- 变量名保持 `STORAGE_S3_*` 前缀（旧 `ARCHIVE_S3_*` 同义仍兼容）；
- 本仓 `docker-compose.yml` 是开发自测用，不作为生产清单。
