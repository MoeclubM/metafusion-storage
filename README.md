# MetaFusion Storage

MetaFusion 物理资产归档与下载中枢：文件本体、内容寻址、直传与绑定。
对应拆分基准见主仓库 [docs/architecture/service-split-migration.md](https://github.com/MoeclubM/MetaFusion/blob/main/docs/architecture/service-split-migration.md) 的 P1 阶段。

## 职责边界

- **拥有**：物理文件、sha256 内容寻址、对象存储直传与预签名、文件→实体的绑定、下载与预览的访问控制。
- **不拥有**：作品/专辑/曲目等目录数据（不复制、不 JOIN 目录库）、收录位置（页码/时间码属目录侧 `locator`）。
- **依赖**：元数据目录服务（实体可见性判定）、账号服务（令牌验签，迁移期可用目录服务兜底）。

存储侧与目录侧的接口只有两条：`GET /api/catalog/entities/{id}`（可见性与 kind）与 `GET /api/auth/me`（迁移期身份兜底）。

## HTTP 契约（`/api/storage`）

| 方法 | 路径 | 鉴权 | 说明 |
| --- | --- | --- | --- |
| POST | `/upload/initiate` | 登录 | 直传第一步：命中 sha256 即秒传；否则签发预签名地址（分片则返回 upload_id 与每片地址）。同一 sha256 的未完成上传由上传者本人续传 |
| POST | `/upload/complete` | 上传者/管理员 | 分片合并并落定大小；单次 PUT 场景只做存在性确认 |
| PUT | `/upload/stream/{asset_id}` | 上传者/管理员 | 服务端流式接收（本地对象模式的主要上传方式，也可作为预签名不可用时的兜底）；落盘前流式计算 sha256 与声明比对 |
| POST | `/bind` | 上传者/管理员 | 绑定到目录实体，带 `binding_role` 用途 |
| DELETE | `/bindings/{id}` | 绑定创建者/上传者/管理员 | 解绑纠错 |
| GET | `/assets/{id}` | 可读 | 文件元数据 + 绑定列表 |
| GET | `/entities/{id}/files` | 实体可见 | 「这个介质/轨道/表达上挂了哪些文件」入口 |
| GET | `/download/{asset_id}` | 可读 | 对象存储模式返回预签名下载地址；本地模式直接流式下发 |
| POST | `/verify-hash` | 可读 | 只给 sha256 = 秒传探测；给 asset_id = 读回对象重算摘要并与声明比对 |
| GET | `/stats` | 管理员 | 完成态文件数与占用字节 |

读取可见性的口径只有一条：**上传者本人或管理员直通，其余人只要任一绑定目标实体可见即可读**。
下载、元数据读取与哈希校验共用这一判定，避免同一份文件在不同接口上出现「能下载不能预览」的差异。

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
| `STORAGE_JWKS_URL` | `http://catalog:8080/api/oidc/jwks` | 验签公钥来源；账号服务上线后改指向 auth |
| `AUTH_JWT_PUBLIC_KEY` | 空 | 静态公钥（PEM 或 base64 PEM）；设置后不再请求 JWKS |
| `AUTH_JWT_ISSUER` / `AUTH_JWT_AUDIENCE` | `https://findverse.cc/api` / `metafusion` | 与主仓库保持一致，避免存量令牌失效 |
| `CATALOG_URL` | `http://catalog:8080` | 目录服务地址（可见性判定） |
| `STORAGE_PRESIGN_TTL_MINUTES` | `120` | 预签名有效期 |
| `STORAGE_MAX_PARTS` | `10000` | 单次上传最大分片数 |
| `STORAGE_MAX_UPLOAD_MB` | `0` | 服务端接收路径的上限，`0` 为不限制（直传路径不受此限） |

服务**刻意不设** `ReadTimeout`/`WriteTimeout`：整盘镜像与视频的上传/下载都可能远超 30 秒，
全局超时会直接截断慢传输（单体当前的 30 秒限制即此原因）。需要收敛时按路由单独加超时。

## 运行

```bash
go run cmd/server/main.go          # 需要 DATABASE_URL 或 DB_* 指向 PostgreSQL
go test ./... && go vet ./...
```

未配置 `STORAGE_S3_ENDPOINT` 时走本地对象模式：`initiate` 返回 `direct_upload_url`，
客户端 `PUT` 原始字节到该地址即完成入库，服务端边收边算 sha256。

## 迁移状态

- 主仓库的 `/api/archive/*`、`/api/playback/*`、`/api/media/*` 仍在服务线上流量；
  本服务的 `/api/storage/*` 是目标契约，**切流由网关按前缀切换**，切换前不影响线上。
- 异步转码/HLS/雪碧图投递、BT 种子与磁力链、分片续传的断点记录尚未实现（契约预留）。
- 版本化迁移待补：当前与主仓库 modules 包一致，用幂等 DDL 建表。
