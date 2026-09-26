package handler

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/MoeclubM/metafusion-storage/internal/auth"
	"github.com/gin-gonic/gin"
)

func browseParams(c *gin.Context) (int, int, bool) {
	limit, err := strconv.Atoi(c.DefaultQuery("limit", "50"))
	if err != nil || limit < 1 || limit > 100 {
		fail(c, http.StatusBadRequest, "invalid_payload")
		return 0, 0, false
	}
	offset, err := strconv.Atoi(c.DefaultQuery("offset", "0"))
	if err != nil || offset < 0 || offset > 1000000 {
		fail(c, http.StatusBadRequest, "invalid_payload")
		return 0, 0, false
	}
	return limit, offset, true
}

func requireModerator(c *gin.Context) bool {
	p := auth.Current(c)
	if p == nil || !p.Can(auth.PermissionAssetModerate) {
		fail(c, http.StatusForbidden, "forbidden")
		return false
	}
	return true
}

func (h *Handler) listAssets(c *gin.Context) {
	if !requireModerator(c) {
		return
	}
	limit, offset, ok := browseParams(c)
	if !ok {
		return
	}
	status := strings.TrimSpace(c.Query("status"))
	if status != "" && status != "pending" && status != "complete" {
		fail(c, 400, "invalid_payload")
		return
	}
	name := strings.TrimSpace(c.Query("name"))
	if len(name) > 100 {
		fail(c, 400, "invalid_payload")
		return
	}
	assets, more, err := h.db.ListAssets(c.Request.Context(), status, name, limit, offset)
	if err != nil {
		fail(c, 500, "module_error")
		return
	}
	c.JSON(200, gin.H{"assets": assets, "limit": limit, "offset": offset, "has_more": more})
}

func (h *Handler) listBindings(c *gin.Context) {
	if !requireModerator(c) {
		return
	}
	limit, offset, ok := browseParams(c)
	if !ok {
		return
	}
	bindings, more, err := h.db.ListBindings(c.Request.Context(), limit, offset)
	if err != nil {
		fail(c, 500, "module_error")
		return
	}
	c.JSON(200, gin.H{"bindings": bindings, "limit": limit, "offset": offset, "has_more": more})
}
