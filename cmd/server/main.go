package main

import (
    "log"
    "os"
    "github.com/gin-gonic/gin"
    "github.com/MoeclubM/metafusion-storage/internal/handler"
)

func main() {
    port := os.Getenv("PORT")
    if port == "" {
        port = "8082"
    }

    r := gin.Default()

    r.GET("/health", func(c *gin.Context) {
        c.JSON(200, gin.H{"status": "ok", "service": "metafusion-storage"})
    })

    api := r.Group("/api/storage")
    {
        api.GET("/entities/:id/files", handler.GetEntityFiles)
        api.POST("/entities/:id/bindings", handler.BindFileToEntity)
        api.POST("/upload/presign", handler.PresignUpload)
        api.GET("/download/:file_id", handler.PresignDownload)
        api.GET("/download/:file_id/torrent", handler.GetTorrent)
        api.POST("/verify-hash", handler.VerifyHash)
    }

    log.Printf("MetaFusion Storage Service listening on port %s", port)
    if err := r.Run(":" + port); err != nil {
        log.Fatalf("Failed to run server: %v", err)
    }
}
