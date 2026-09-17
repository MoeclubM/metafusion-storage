# 存储管理台（storage-admin）

MetaFusion 存储域自带的管理界面。**独立应用 + 同域路径 + 网关按路径聚合**，
决议见主仓库 [多项目解耦审计](https://github.com/MoeclubM/MetaFusion/blob/main/docs/architecture/decoupling-audit-2026-09.md) §7.3：
管理面归各服务自己，改一域的管理界面只重发那一域的镜像，主前端不再是所有服务的发布闸门。

## 冻结契约

| 项 | 值 |
| --- | --- |
| basePath | `/admin/storage` |
| 容器内端口 | `3000` |
| 健康端点 | `GET /admin/storage/api/health` → `{"ok":true,"service":"storage-admin"}`（不依赖登录态） |
| 网关路径 | `/admin/storage/`（主仓库 `deploy/nginx.conf` 反代到 `storage-admin:3000`） |
| 数据面 | 同域 `/api/storage/*`（由网关按域分流回存储服务，不使用 rewrites） |
| 构建 | 主仓库 `deploy/docker-compose.yml` 的 `storage-admin` 服务：context = **本仓库根**、dockerfile = `admin/Dockerfile` |

改这里任何一项都要同步主仓库的 `deploy/nginx.conf`、`deploy/docker-compose.yml` 与文档矩阵。

## 页面与用到的端点

| 页面 | 路径 | 端点 | 权限 |
| --- | --- | --- | --- |
| 用量总览 | `/admin/storage/` | `GET /api/storage/stats` | `storage.asset.moderate`（缺码时界面按块降级并说明） |
| 资产查询 | `/admin/storage/assets` | `GET /api/storage/assets/:id`、`GET /api/storage/assets/:id/content`（内联预览）、`GET /api/storage/download/:assetId` | 读可见性由服务端判定：上传者本人、审核者，或任一绑定目标实体可见 |
| 绑定解绑 | `/admin/storage/bindings` | `DELETE /api/storage/bindings/:id`、`GET /api/storage/entities/:id/files`、`GET /api/storage/assets/:id` | 解绑限绑定创建者 / 上传者 / 审核者 |

三处"照实说"的地方（不要改成看起来更漂亮的样子）：

1. **不画占用率**：`/stats` 只返回 `assets` 与 `bytes`，**没有配额字段**，进度条的分母只能靠编。
   页面写明统计口径是 `status='complete'` 的资产，并给出原始字节数。
2. **404 有两种含义**：资产查询对"不存在"与"当前账号不可读"一律回 404（`internal/handler/files.go` 的
   `readable`），界面不假装能区分，两句话都写出来。
3. **解绑不幂等**：`DELETE /bindings/:id` 先按 id 查这一行再删，第二次调用只剩 `not_found`。
   界面讲成"该绑定已不存在（可能已被别人解除）"，并**重新取数**（列表以服务端为准），不当成失败。

存储服务没有"按 id 读绑定"的端点，因此解绑入口分三种：按资产查（能重新取数）、按实体查
（`/entities/:id/files`，能重新取数）、直接按绑定 id（没有可刷新的列表，只报结果——界面已写明）。

## 本地开发

```bash
cd admin
bun install
bun run dev          # http://127.0.0.1:3000/admin/storage/
```

本地默认端口与容器一致（3000）。`basePath` 是构建期常量，因此本地地址也带前缀。

**同域是前提**：数据面走相对路径 `/api/storage/*`，会话 cookie（`mf_session`，httpOnly）只对同域发送。
所以本地要连真实数据，最省事的做法是让请求先过网关（同域部署下的正式路径）。要指向别的地址可以设：

| 环境变量 | 默认 | 说明 |
| --- | --- | --- |
| `NEXT_PUBLIC_STORAGE_API_BASE` | `/api/storage` | 数据面前缀。设成绝对地址即跨域，需要目标侧放行 CORS 与同名 cookie（存储服务当前不发 CORS 头），一般别改。 |
| `NEXT_PUBLIC_LOGIN_PATH` | `/login` | 未登录时跳转的主站登录页；同域根路径，登录后带 `?redirect=` 回跳。 |

两个变量都是 `NEXT_PUBLIC_*`，**在构建期内联**，运行期改环境变量无效。

## 构建镜像

镜像由主编排负责构建（上下文是仓库根，Dockerfile 在 `admin/Dockerfile`）：

```bash
# 在存储仓库根执行，等价于主编排里的 storage-admin 服务
docker build -f admin/Dockerfile -t metafusion-storage-admin .
```

忽略文件是仓库根的 `.dockerignore`（上下文根只能有一处），`admin/` 下不再放一份不会生效的副本。

## 验证

```bash
cd admin
bun run typecheck      # tsc --noEmit
bun run i18n:check     # 四语字典键集合 / 占位符 / 源码引用一致性
bun run build          # next build（standalone 产物）
```

CI 里跑的是同一组命令（`.github/workflows/ci.yml` 的 `admin` 作业）。健康端点可在构建后直接验：

```bash
bun run build && bun run start &
curl -s http://127.0.0.1:3000/admin/storage/api/health   # {"ok":true,"service":"storage-admin"}
```

## 代码结构与来源说明

```
src/app/            页面（overview / assets / bindings）与 /api/health 路由
src/components/     AppShell、会话门、绑定表、UI 原件
src/lib/            存储服务客户端、错误码到文案的映射、格式化与 uuid 工具
src/messages/       四语字典（本域键，四语键集合由脚本断言）
src/shared/         抄自主仓库的共享面：设计 token（theme/）、i18n 骨架、会话客户端
```

`src/shared/theme/*`、`src/shared/i18n/*` 与 `tailwind.config.ts`、`postcss.config.mjs` 是
**`MetaFusion/frontend` 对应文件的逐字副本**（文件头已注明来源与原因）：解耦审计要求共享层先行，
但跨仓库共享包需要先有发布渠道，因此本批次各自复制最小共享面，等共享层（`packages/` 或协议层 SDK）
落地后替换为依赖引用。改配色、圆角、语言维度请改主仓库那份再同步过来。
