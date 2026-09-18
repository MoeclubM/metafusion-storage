package config

import (
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config 是存储服务的运行配置，全部来自环境变量；缺失时回落到可用的开发默认值。
// S3/归档相关变量沿用主仓库 deploy/docker-compose.yml 的 ARCHIVE_* 命名，
// 拆分期两侧可以共用同一份 .env，不需要两套变量名。
type Config struct {
	Port string
	// TrustedProxies 是可信反向代理的 IP/CIDR 列表（TRUSTED_PROXIES，逗号分隔）。
	// 只有对端落在列表里时 gin 才采信 X-Forwarded-For，否则 ClientIP() 回退 RemoteAddr；
	// 留空表示用 internal/nettrust 的保守默认（回环 + RFC1918 私网），"none" 表示入口无代理。
	TrustedProxies string
	// DatabaseURL 为 PostgreSQL 连接串；为空时用 DB_* 拼装。
	DatabaseURL string
	// Root 本地对象模式的根目录（也用于上传暂存）。
	Root string
	// S3Endpoint 服务端访问对象存储的地址；为空即本地对象模式（无需 RustFS 也能开发）。
	S3Endpoint string
	// S3PublicEndpoint 客户端直传时使用的对外地址：预签名 URL 的 host 参与签名，
	// 因此必须用浏览器可达的地址签发，否则反代后签名校验失败。
	S3PublicEndpoint string
	S3AccessKey      string
	S3SecretKey      string
	S3Bucket         string
	S3TLS            bool
	// JWKSURL 验签公钥来源。auth 服务上线前指向 catalog 的 /api/oidc/jwks，
	// 上线后只改环境变量，不需要改代码。
	JWKSURL string
	// JWTPublicKeyPEM 静态公钥（PEM 或 base64 后的 PEM）；设置后不再请求 JWKS。
	JWTPublicKeyPEM string
	JWTIssuer       string
	JWTAudience     string
	// AuthURL 账号服务地址，仅用于存量不透明会话令牌的兜底解析（GET /api/auth/me）。
	// 留空即"只接受 JWT"：身份问题只问账号服务，不查任何人的库。
	AuthURL string
	// CatalogURL 元数据服务地址：实体可见性必须问它，存储侧不复制目录数据。
	CatalogURL string
	// PresignTTL 预签名有效期；MaxPartCount 单次上传的最大分片数。
	PresignTTL   time.Duration
	MaxPartCount int
	// MaxUploadMB 服务端接收路径（本地对象模式/兜底）的单次上传上限，0 表示不限制。
	// 直传路径的上限由对象存储与网关决定，不受这里影响。
	MaxUploadMB int
	// VerifyMaxMB 是 complete 阶段服务端回读对象、重算 sha256 的**单对象大小上限**：
	// 直传路径的内容没有被服务端逐字节收过，只能在落定前整份读回一次，代价随对象线性增长。
	// 超限即显式失败（hash_verify_too_large），资产留在 pending，绝不"跳过校验但置 complete"。
	// 0 表示不限制——与大文件优先的默认取向一致，需要收敛时由运维按对象存储带宽设定。
	VerifyMaxMB int
	// VerifyTimeout 是同一段回读的墙钟上限：读不完即失败（verify_timeout），同样不跳过校验。
	// 0 表示不限制，与"刻意不设 ReadTimeout/WriteTimeout"的大文件取向一致。
	VerifyTimeout time.Duration
}

func Load() Config {
	c := Config{
		Port:             env("PORT", "8082"),
		TrustedProxies:   env("TRUSTED_PROXIES", ""),
		DatabaseURL:      env("DATABASE_URL", ""),
		Root:             env("STORAGE_ROOT", env("ARCHIVE_PATH", "./storage-data")),
		S3Endpoint:       env("STORAGE_S3_ENDPOINT", env("ARCHIVE_S3_ENDPOINT", "")),
		S3PublicEndpoint: env("STORAGE_S3_PUBLIC_ENDPOINT", env("ARCHIVE_S3_PUBLIC_ENDPOINT", "")),
		S3AccessKey:      env("STORAGE_S3_ACCESS_KEY", env("ARCHIVE_S3_ACCESS_KEY", "")),
		S3SecretKey:      env("STORAGE_S3_SECRET_KEY", env("ARCHIVE_S3_SECRET_KEY", "")),
		S3Bucket:         env("STORAGE_S3_BUCKET", env("ARCHIVE_S3_BUCKET", "metafusion-master")),
		S3TLS:            envBool("STORAGE_S3_TLS", env("ARCHIVE_S3_TLS", "true") != "false"),
		JWKSURL:          env("STORAGE_JWKS_URL", "http://auth:8081/api/oidc/jwks"),
		JWTPublicKeyPEM:  env("AUTH_JWT_PUBLIC_KEY", ""),
		JWTIssuer:        env("AUTH_JWT_ISSUER", "https://findverse.cc/api"),
		JWTAudience:      env("AUTH_JWT_AUDIENCE", "metafusion"),
		AuthURL:          env("AUTH_URL", ""),
		CatalogURL:       env("CATALOG_URL", "http://backend:8080"),
		PresignTTL:       time.Duration(envInt("STORAGE_PRESIGN_TTL_MINUTES", 120)) * time.Minute,
		MaxPartCount:     envInt("STORAGE_MAX_PARTS", 10000),
		MaxUploadMB:      envInt("STORAGE_MAX_UPLOAD_MB", 0),
		VerifyMaxMB:      envInt("STORAGE_VERIFY_MAX_MB", 0),
		VerifyTimeout:    time.Duration(envInt("STORAGE_VERIFY_TIMEOUT_SECONDS", 0)) * time.Second,
	}
	if c.S3PublicEndpoint == "" {
		c.S3PublicEndpoint = c.S3Endpoint
	}
	if c.DatabaseURL == "" {
		c.DatabaseURL = buildDSN()
	}
	return c
}

// buildDSN 用 url.URL 拼连接串：口令里的 @ : / ? # 等字符必须转义，
// 直接字符串拼接会在这些字符上拼出非法 DSN（或连错主机）。
func buildDSN() string {
	u := url.URL{
		Scheme: "postgres",
		Host:   env("DB_HOST", "localhost") + ":" + env("DB_PORT", "5432"),
		Path:   env("DB_NAME", "metafusion_db"),
		User:   url.UserPassword(env("DB_USER", "metafusion"), os.Getenv("DB_PASSWORD")),
	}
	q := u.Query()
	q.Set("sslmode", env("DB_SSLMODE", "disable"))
	u.RawQuery = q.Encode()
	return u.String()
}

func env(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}

func envBool(k string, def bool) bool {
	v := strings.TrimSpace(os.Getenv(k))
	if v == "" {
		return def
	}
	return v != "false" && v != "0"
}

func envInt(k string, def int) int {
	v := strings.TrimSpace(os.Getenv(k))
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return def
	}
	return n
}
