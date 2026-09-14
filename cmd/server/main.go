package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/MoeclubM/metafusion-storage/internal/auth"
	"github.com/MoeclubM/metafusion-storage/internal/catalog"
	"github.com/MoeclubM/metafusion-storage/internal/config"
	"github.com/MoeclubM/metafusion-storage/internal/handler"
	"github.com/MoeclubM/metafusion-storage/internal/objects"
	"github.com/MoeclubM/metafusion-storage/internal/store"
)

func main() {
	cfg := config.Load()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	db, err := store.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("storage database connection failed: %v", err)
	}
	defer db.Close()
	if err = db.Init(ctx); err != nil {
		log.Fatalf("storage schema initialization failed: %v", err)
	}

	objs, err := objects.New(ctx, cfg)
	if err != nil {
		log.Fatalf("object storage initialization failed: %v", err)
	}
	if objs.Local() {
		log.Print("STORAGE_S3_ENDPOINT is unset; using the local object store under " + cfg.Root)
	}

	cat := catalog.New(cfg.CatalogURL)
	verifier, err := auth.New(cfg)
	if err != nil {
		log.Fatalf("token verifier initialization failed: %v", err)
	}
	// 存量兜底：浏览器可能还持有登录时的不透明会话令牌（非 JWT）。身份只能问账号服务，
	// 因此兜底指向 AUTH_URL；未配置时退化为"只接受 JWT"（fail closed），不会静默放行。
	if cfg.AuthURL != "" {
		verifier.SetFallback(auth.NewSessionClient(cfg.AuthURL, 5*time.Second))
	}

	r := gin.New()
	r.Use(gin.Logger(), gin.Recovery())
	r.SetTrustedProxies(nil)
	r.Use(func(c *gin.Context) {
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")
		c.Header("X-Frame-Options", "SAMEORIGIN")
		// 切流自检用：响应头标明是哪个服务答复的，便于确认网关把前缀切到了目标上游。
		c.Header("X-MetaFusion-Service", "metafusion-storage")
		c.Next()
	})

	handler.New(db, objs, cat, verifier, cfg).Register(r)

	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "live", "service": "metafusion-storage"})
	})
	r.GET("/ready", func(c *gin.Context) {
		check, cancel := context.WithTimeout(c.Request.Context(), 2*time.Second)
		defer cancel()
		if err := db.DB().PingContext(check); err != nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"status": "unavailable"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"status": "ready", "dependencies": []string{"postgres"}})
	})

	// 刻意不设 ReadTimeout/WriteTimeout：大文件直传与本地对象模式下的整份下发
	// 都可能远超 30 秒，全局写超时会直接截断慢速上传/下载（单体当前的 30s 限制即此因）。
	// 需要限制时按路由加超时，而不是给整个服务设一个会把长传输切掉的全局值。
	server := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           r,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	done := make(chan error, 1)
	go func() {
		log.Print("MetaFusion storage service ready")
		done <- server.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdown); err != nil {
			log.Fatalf("server shutdown error: %v", err)
		}
	case err := <-done:
		if errors.Is(err, http.ErrServerClosed) {
			return
		}
		log.Fatalf("server error: %v", err)
	}
}
