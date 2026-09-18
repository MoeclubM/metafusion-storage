package handler

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/MoeclubM/metafusion-storage/internal/store"
)

// 库里的行是 complete、对象却不在对象存储里——线上自托管封面就是这个状态
// （同一资源元数据接口 200，内容端点稳定 503）：必须回 404 object_missing，
// 而不是 503 storage_unavailable。两者混为一谈时，"内容已经没了"看起来只是
// "对象存储暂时不可用"，重试、扩容、换端点都不会让内容出现。
func TestAssetContentReportsMissingObject(t *testing.T) {
	h := newUploadHarness(t, false)
	const uploader = "11111111-1111-1111-1111-111111111111"
	owner := h.token(uploader)
	id := uuid.NewString()
	sha := strings.Repeat("ab", 32)
	if err := h.db.CreateAsset(context.Background(), store.Asset{
		ID:        id,
		SHA256:    sha,
		SizeBytes: 12,
		MimeType:  "image/png",
		FileName:  "cover.png",
		// 键按真实格式给：这里要测的是"键上没有对象"，不是键合不合法。
		ObjectKey:  "objects/ab/" + sha + "/cover.png",
		Status:     "complete",
		UploaderID: uploader,
	}); err != nil {
		t.Fatalf("建资产失败: %v", err)
	}

	w := h.getContent(owner, id)
	if w.Code != 404 {
		t.Fatalf("对象缺失应 404 object_missing，实际 %d（%s）", w.Code, w.Body.String())
	}
	var body struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("解析错误体失败: %v（%s）", err, w.Body.String())
	}
	if body.Error != "object_missing" {
		t.Fatalf("错误码 = %q，期望 object_missing", body.Error)
	}
}
