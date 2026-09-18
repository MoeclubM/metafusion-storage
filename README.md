# MetaFusion Storage

MetaFusion 物理资产归档与下载中枢：文件本体、内容寻址、直传与绑定。
对应拆分基准见主仓库 [docs/architecture/service-split-migration.md](https://github.com/MoeclubM/MetaFusion/blob/main/docs/architecture/service-split-migration.md) 的 P1 阶段。

## 职责边界

- **拥有**：物理文件、sha256 内容寻址、对象存储直传与预签名、文件→实体的绑定、下载与预览的访问控制。
- **不拥有**：作品/专辑/曲目等目录数据（不复制、不 JOIN 目录库）、收录位置（页码/时间码属目录侧 `locator`）。
- **依赖**：元数据目录服务（实体可见性判定）、账号服务（令牌验签，迁移期可用目录服务兜底）。

存储侧与目录侧的接口只有一条：`GET /api/catalog/entities/{id}`（可见性与 kind）；实体已合并时再取一次
`/api/catalog/entities/{id}/resolve` 跟随重定向（目录侧把合并事实写进 `catalog.outbox`，**当前没有跨服务消费者**，改引用是引用方自己的事；见主仓库审计文档 §5）。
身份解析不走目录服务：存量不透明令牌的兜底问 `AUTH_URL`（账号服务）。

## HTTP 契约（`/api/storage`）

| 方法 | 路径 | 鉴权 | 说明 |
| --- | --- | --- | --- |
| POST | `/upload/initiate` | 登录 + `upload` | 直传第一步：命中 sha256 即秒传；否则签发预签名地址（分片则返回 upload_id 与每片地址）。同一 sha256 的未完成上传由上传者本人续传 |
| POST | `/upload/complete` | 登录 + `upload`；资产属他人时另需审核者 | 分片合并后**服务端回读对象重算 sha256**，与声明一致才置 complete 并记 `hash_verified`；不一致返回 `hash_mismatch`（409），超限/超时返回 `hash_verify_too_large`（413）/`verify_timeout`（408） |
| PUT | `/upload/stream/{asset_id}` | 登录 + `upload`；资产属他人时另需审核者 | 服务端流式接收（本地对象模式的主要上传方式，也可作为预签名不可用时的兜底）；落盘前流式计算 sha256 与声明比对 |
| POST | `/bind` | 登录 + `upload`；资产属他人时另需审核者 | 绑定到目录实体，带 `binding_role` 用途 |
| DELETE | `/bindings/{id}` | 绑定创建者/上传者/审核者 | 解绑纠错 |
| GET | `/assets/{id}` | 可读 | 文件元数据 + 绑定列表 |
| GET | `/assets/{id}/content` | 可读 | **原样**内联分发对象内容（不转码）：给目录数据里需要长期引用、能被 `<img>` 直接加载的地址用；`download` 在对象存储模式下只回预签名地址（会过期、Host 是对象存储端点），不能当稳定地址 |
| GET | `/entities/{id}/files` | 实体可见 | 「这个介质/轨道/表达上挂了哪些文件」入口 |
| GET | `/download/{asset_id}` | 可读 | 对象存储模式返回预签名下载地址；本地模式直接流式下发 |
| POST | `/verify-hash` | 可读 / 按 asset 校验需登录 | 只给 sha256 = 秒传探测（只认 `hash_verified=true` 的资产）；给 asset_id = 读回对象重算摘要并与声明比对，同样受回读上限约束 |
| GET | `/stats` | 审核者 | 完成态文件数与占用字节 |

读取可见性的口径只有一条：**上传者本人或审核者直通，其余人只要任一绑定目标实体可见即可读**。
下载、元数据读取与哈希校验共用这一判定，避免同一份文件在不同接口上出现「能下载不能预览」的差异；
`/assets/{id}/content` 也走同一判定（响应只进私有缓存：可见性按请求判定，不能被共享缓存复用）。

### 权限码

授权以账号服务下发的权限码为准（访问令牌的 `permissions` 声明，或 `GET /api/auth/me`），
集中判定在 `internal/auth/permission.go` 的 `Principal.Can`：码优先（`*` 通配即全权），
**令牌没带 `permissions` 时按历史角色兜底**（`admin` 放行本服务全部码，其余角色不放行），
因此老令牌与尚未配置权限组的实例不会被拒。

| 码 | 含义 | 当前覆盖 |
| --- | --- | --- |
| `storage.asset.upload` | 上传资源：创建自己的资产、完成直传、绑定用途 | 路由表中的 `upload/initiate`、`upload/complete`、`upload/stream`、`bind` 四个写接口（缺码 `403 forbidden`）；登录本身仍由 401 判定。`unbind`、读接口与 `/stats` 不收此码 |
| `storage.asset.moderate` | 审核资源：完成/接收/绑定/解绑/读取他人的资产、全局统计 | 读表里所有标「审核者」的位置 |

代码里的判定不做角色比较：给某个组授予 `storage.asset.moderate` 即可让成员承担审核（例如建一个
`storage_moderator` 组），不必再改本服务代码。

**个人访问令牌（PAT）**：`Authorization: Bearer mfp_…`（`mfp_` + 43 位 base62）由账号服务的
`POST /api/auth/tokens/introspect` 判定，本服务**不读账号库、不签发、不落盘凭据**。内省拿到的身份与 JWT 同形
（id / username / role / permissions），但**权限一律按 permissions 里的码判定**：即使权限集合为空也绝不回落到
角色兜底或历史的"登录即可"边界——PAT 的权限就是账号服务算好的"用户自身权限 ∩ scopes"，否则 `scopes=[]`
的管理员令牌会变成全权令牌（创建端点已禁止空 scopes，这是第二道防线）。

- 内省结果按明文 sha256 **进程内缓存 60 秒**（同键并发只打一次账号服务，缓存有上限与逐出），
  因此**吊销与过期最长 60 秒后才在本服务生效**；
- 本地先做形态预检（`mfp_` + 43 位 base62），明显非法的明文直接 `401 invalid_token`，不打账号服务；
- 令牌无效 / 已吊销 / 已过期 / 账号被封禁 → `401 invalid_token`（共用一个稳定机器码，不细分原因）；
- 账号服务不可达、内省端点未上线或未配置 `AUTH_URL` → `503 auth_unavailable`，**不是 401**：
  那是依赖故障，回 401 会让 bot/CI 以为凭据有问题去换令牌（换令牌解决不了，重试才行）；
- 状态码映射的边界（别按字面"非 200 都当不认"改回去）：只有 `401` / `403` 是账号服务对**令牌本身**的判定，
  才回 `401 invalid_token`；`503`（账号服务读不动库）、`404`（内省端点还没上线，滚动部署期）、
  `429`（内省限流）与 5xx / 网络超时都**不是**"令牌无效"的证据，一律回 `503 auth_unavailable`——
  照字面把它们也回 401，会让 bot/CI 把有效令牌当废令牌丢掉（换令牌解决不了这些故障，重试才行）；
- PAT 请求不回落 `mf_session` Cookie（浏览器里可能同时有另一个用户的会话），也不产出 Cookie。
  实现与回归见 `internal/auth/pat.go`；三处（目录 / 互动 / 存储）必须同改，口径见主仓库 README 的同名字段。



### 绑定用途（binding_role）

`binding_role` 用字段码表达用途，默认 `master_archive`，取值需匹配 `^[a-z][a-z0-9_]{0,31}$`，
不设封闭枚举：`track_audio`（分轨音频）、`disc_image`（整碟镜像）、`video`、`scans`（扫描件）、
`subtitle`、`ebook` 等由运维与编目约定，新增用途不需要改代码。

## 环境变量

| 变量 | 默认 | 说明 |
| --- | --- | --- |
| `PORT` | `8082` | 监听端口 |
| `DATABASE_URL` | 由 `DB_*` 拼装 | PostgreSQL 连接串（本服务只使用 `storage` schema） |
| `STORAGE_ROOT` | `./storage-data` | 本地对象模式根目录与直传暂存目录 |
| `STORAGE_S3_ENDPOINT` | 空 | 为空即本地对象模式（无需 RustFS）；兼容旧名 `ARCHIVE_S3_ENDPOINT` |
| `STORAGE_S3_PUBLIC_ENDPOINT` | 同内部端点 | 客户端直传使用的对外地址。SigV4 覆盖 Host，必须用浏览器可达的地址签发，否则反代后签名校验失败 |
| `STORAGE_S3_ACCESS_KEY` / `_SECRET_KEY` / `_BUCKET` / `_TLS` | — | 对象存储凭据与桶（旧名 `ARCHIVE_S3_*` 同义） |
| `STORAGE_JWKS_URL` | `http://auth:8081/api/oidc/jwks` | 验签公钥来源：账号服务是唯一签发方 |
| `AUTH_URL` | 空 | 账号服务地址：存量不透明会话令牌的兜底解析（`GET /api/auth/me`）与 PAT 内省（`POST /api/auth/tokens/introspect`）；留空即"只接受 JWT"且 PAT 一律 `503 auth_unavailable` |
| `AUTH_JWT_PUBLIC_KEY` | 空 | 静态公钥（PEM 或 base64 PEM）；设置后不再请求 JWKS |
| `AUTH_JWT_ISSUER` / `AUTH_JWT_AUDIENCE` | `https://findverse.cc/api` / `metafusion` | 与主仓库保持一致，避免存量令牌失效 |
| `CATALOG_URL` | `http://backend:8080` | 目录服务地址（可见性判定） |
| `STORAGE_PRESIGN_TTL_MINUTES` | `120` | 预签名有效期 |
| `STORAGE_MAX_PARTS` | `10000` | 单次上传最大分片数 |
| `STORAGE_MAX_UPLOAD_MB` | `0` | 服务端接收路径的上限，`0` 为不限制（直传路径不受此限） |
| `STORAGE_VERIFY_MAX_MB` | `0` | complete 阶段回读重算 sha256 的**单对象大小上限**，`0` 为不限制；超限返回 `hash_verify_too_large`，资产留在 pending，不置完成 |
| `STORAGE_VERIFY_TIMEOUT_SECONDS` | `0` | 同一段回读的墙钟上限（秒），`0` 为不限制；超时返回 `verify_timeout`，同样不置完成 |

服务**刻意不设** `ReadTimeout`/`WriteTimeout`：整盘镜像与视频的上传/下载都可能远超 30 秒，
全局超时会直接截断慢传输（单体当前的 30 秒限制即此原因）。需要收敛时按路由单独加超时。

两个 `STORAGE_VERIFY_*` 默认都不限制，与大文件优先的取向一致；它们的取舍是明确的：

- 预签名直传的内容**没有经过服务端**，`initiate` 采信的 sha256 只是客户端声明，
  因此 `complete` 必须把对象整份读回、重算摘要才能落定——代价随对象线性增长（一次完整读）。
  **对象越大越可能撞上限**：超过上限的对象要显式失败（不会"跳过校验但置 complete"），
  这类大文件应改走服务端流式接收 `PUT /upload/stream/{asset_id}`（边收边算，没有二次读回成本），
  或分片上传并在 `complete` 前自行核对；
- 客户端可以用 `POST /verify-hash`（带 `asset_id`）在收尾前先自检一次，提前拿到 `verified=false`，
  不必等到 `complete` 才失败。

配置了 `STORAGE_S3_ENDPOINT` 时，服务在启动阶段**自己保证桶存在**（`internal/objects` 的 `ensureBucket`：
先 `BucketExists` 再 `MakeBucket`，并发下按"已存在"容忍，幂等）。
桶不再由一次性的 `minio/mc` 初始化容器创建——该镜像已从 Docker Hub 撤下，拉不到会让整条部署链失败；
桶归属服务本身，判定条件与"服务能否连上对象存储"完全一致，因此也不需要额外的启动顺序依赖。

### 完成上传时的内容校验（P1 完整性约束）

内容寻址的前提是"键上的内容确实等于该 sha256"。直传路径上这个前提**不由上传者承诺**，因此：

- `complete` 在合并后回读对象、重算 sha256：一致才置 `complete` 并写 `hash_verified=true`；
  不一致返回 `409 hash_mismatch`，资产留在 `pending`、`fail_reason` 记下原因，**绝不发布**；
  同时删掉那个对不上声明的内容寻址键，避免它继续占位；
- **秒传/查重只复用 `hash_verified=true` 的资产**（`internal/store` 的 `VerifiedAssetByHash`）：
  `initiate`、`verify-hash` 的秒传探测都走这条判据，未验证命中一律按"没有"处理并继续正常上传；
  `CompleteAsset` 本身也只认 `hash_verified=true` 的行，任何新增上传路径都无法把未验内容推成完成态；
- 回读校验的两个上限见上方环境变量；超限/超时都是**可识别的显式失败**，不允许静默降级；
- 失败上传留下的 `pending` 资产仍然占着该 sha256 的唯一索引（内容寻址只登记一份），
  由**上传者本人**重传正确内容即可收尾；同一 sha256 换人上传会被唯一索引挡住。

```bash
# 冒烟：正确内容 → complete 200 且 hash_verified=true
#       等长的错内容 → complete 409 hash_mismatch，资产 pending，该 sha256 秒传不再命中
go test -count=1 ./internal/handler/ ./internal/objects/   # 两种对象模式各覆盖一遍
```

## 运行

```bash
go run cmd/server/main.go          # 需要 DATABASE_URL 或 DB_* 指向 PostgreSQL
go test ./... && go vet ./...
```

未配置 `STORAGE_S3_ENDPOINT` 时走本地对象模式：`initiate` 返回 `direct_upload_url`，
客户端 `PUT` 原始字节到该地址即完成入库，服务端边收边算 sha256。

## 数据库结构与迁移

表结构在 `internal/store/migrations/*.up.sql`（基线 `000001_init.up.sql` + 审计表 `000002_audit_log.up.sql`），
由 `internal/store` 在启动时应用（`Init` → `Migrate`）；每个版本一个事务，
DDL 与记账同事务提交，账本表是 `storage.schema_migrations(version, applied_at)`。

- 迁移文件用 `go:embed` 打进二进制：镜像里只有 `/app/storage-server`，文件必须随二进制走；
- 每条语句都幂等（`IF NOT EXISTS` / `ADD COLUMN IF NOT EXISTS`）：老实例重复启动不改结构，
  历史实例缺列（例如后补的 `fail_reason`）也由同一份文件补齐，不再另写"补丁迁移"；
- 迁移期间取事务级 advisory lock（键 740204，与目录服务的 740202、账号服务的 740203 分开）：
  多副本同时启动时只让一个实例执行 DDL，其余实例等它提交后按账本空转；
- 审计表在**跨服务共用的 `audit` schema**（不属于本服务的领域数据）：迁移文件里在同一事务内
  另取跨服务建表锁 740205，与上面的 740204 是两把锁，不会互相顶掉；
- 账本只记"这一版执行过"，不校验结构本身。手工删过表而账本还在时启动不会重建，
  这种情况删掉对应账本行（`DELETE FROM storage.schema_migrations WHERE version='000001_init'`）再重启。

`sql/roles.example.sql` 是数据层隔离（B4）的准备件：给 `metafusion_storage` 角色**只授 `storage` schema**，
**编排尚未启用**；手工执行该文件并把 `DATABASE_URL` 换成该角色即生效，代码侧不需要改动。
审计表是例外：它在跨服务共用的 `audit` schema 里（可能由别的服务先建），因此该文件对 `audit`
另授 `USAGE` + `SELECT, INSERT`，否则本服务的审计行会全部写失败（业务不受影响，但留痕静默缺失）。

## 审计留痕

写路由（`POST/PUT/PATCH/DELETE`）成功与失败都落一行到跨服务共用的 `audit.audit_log`
（契约 `docs/architecture/audit-log.md`，本仓库实现在 `internal/audit`）。动作码按路由登记在
`internal/handler/audit.go` 的 `auditActions`：

| 路由 | 动作码 |
| --- | --- |
| `POST /api/storage/upload/initiate` | `asset.upload_initiated` |
| `POST /api/storage/upload/complete` | `asset.upload_completed` |
| `PUT /api/storage/upload/stream/:assetId` | `asset.upload_streamed` |
| `POST /api/storage/bind` | `binding.created` |
| `DELETE /api/storage/bindings/:id` | `binding.removed` |

- `POST /api/storage/verify-hash` 是**刻意豁免**的写路由：它是读语义的探测与摘要回读校验，
  且探测允许匿名，写审计等于给只读探测开一个刷表入口（理由写在 `auditExempt`，守卫测试要求非空）；
- 写入是**非阻塞旁路**：队列满或落库失败只记日志、丢一行，绝不回滚业务写入；
  流式上传只记元数据（assetId / sha256 / size / mime），不读也绝不落请求体；
- 本服务**没有**审计读取端点：查询面在账号服务的 `GET /api/admin/audit-logs`；
- 新增写端点必须同时登记动作码，否则 `TestWriteRoutesAreAudited`（遍历 gin 路由树）会失败。

## 测试

```bash
go test ./...                 # 全部离线可跑：路由契约、内容寻址键、可见性边界、直传链路
STORAGE_TEST_DSN='postgres://…/metafusion_storage_test' go test ./...   # 追加真实数据库回归
```

其中 `internal/objects/s3_test.go` 用一个只实现必要动作的**假 S3 端点**端到端覆盖了
"建分片会话 → 逐片签发预签名地址 → 客户端 PUT → 合并 → 回读校验"这条链路
（单体原本只做服务端中转上传，这段代码在拆分时才出现，也是最容易只在真实环境暴露问题的地方）。
它已经抓到过一个真实缺陷：分片合并后若采信客户端库返回的 Size（S3 合并响应体里没有长度，该值为 0），
"声明大小 vs 实际大小"的校验会把每一次分片上传都判成 `size_mismatch`——现在改为 HEAD 回读真实大小。

## 迁移状态

- 主仓库的 `/api/archive/*`、`/api/playback/*`、`/api/media/*` **已退役**（网关不再为它们单列 location，相关实现与表已删除）；
  本服务的 `/api/storage/*` 是唯一契约，切流已完成，回退按网关前缀切换。
- 异步转码/HLS/雪碧图投递、BT 种子与磁力链、分片续传的断点记录尚未实现（契约预留）。
