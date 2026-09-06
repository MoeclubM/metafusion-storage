package handler

import (
    "net/http"
    "github.com/gin-gonic/gin"
)

func GetEntityFiles(c *gin.Context) {
    c.JSON(http.StatusOK, gin.H{
        "target_entity_id": c.Param("id"),
        "files":            []any{},
    })
}

func BindFileToEntity(c *gin.Context) {
    c.JSON(http.StatusNotImplemented, gin.H{"message": "Storage service scaffold ready"})
}

func PresignUpload(c *gin.Context) {
    c.JSON(http.StatusNotImplemented, gin.H{"message": "Storage service scaffold ready"})
}

func PresignDownload(c *gin.Context) {
    c.JSON(http.StatusNotFound, gin.H{"error": "file_not_found"})
}

func GetTorrent(c *gin.Context) {
    c.JSON(http.StatusNotFound, gin.H{"error": "torrent_not_found"})
}

func VerifyHash(c *gin.Context) {
    c.JSON(http.StatusOK, gin.H{"valid": true})
}
