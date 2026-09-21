package handler

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/MoeclubM/metafusion-storage/internal/catalog"
	"github.com/MoeclubM/metafusion-storage/internal/config"
	"github.com/MoeclubM/metafusion-storage/internal/objects"
	"github.com/MoeclubM/metafusion-storage/internal/store"
	"github.com/MoeclubM/metafusion-storage/internal/testutil"
)

// X01 读聚合回归：A→C 合并后，绑定仍挂在旧 ID 上（合并只广播事件、不改写引用），
// 从旧 ID 读必须聚合“请求 ID + 存活身份”两 ID，且按绑定 ID 去重。
// 待反向全量：从存活身份 C 直接读时，历史 A 上的行仍不可见——目录“canonical→历史别名”
// 反向契约未落地（见 catalog.AliasSet 注释）。本用例把该缺口锁成显式断言，不是静默遗漏。
func TestListEntityFilesAggregatesRequestAndCanonical(t *testing.T) {
	dsn := testutil.DSN(t) // 未设置 STORAGE_TEST_DSN 时跳过
	ctx := context.Background()
	st, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	if err = st.Init(ctx); err != nil {
		t.Fatalf("init schema: %v", err)
	}

	oldID, canonicalID := uuid.NewString(), uuid.NewString()
	mkAsset := func(name string) string {
		t.Helper()
		id := uuid.NewString()
		sum := sha256.Sum256([]byte(id))
		if err := st.CreateAsset(ctx, store.Asset{
			ID: id, SHA256: hex.EncodeToString(sum[:]), SizeBytes: 3, DeclaredSize: 3,
			MimeType: "application/octet-stream", FileName: name, ObjectKey: "probe/" + id,
			Status: "complete", UploaderID: uuid.NewString(),
		}); err != nil {
			t.Fatalf("create asset: %v", err)
		}
		return id
	}
	oldAsset, canonicalAsset := mkAsset("old.flac"), mkAsset("new.flac")
	mkBind := func(assetID, target string) {
		t.Helper()
		if err := st.Bind(ctx, store.Binding{
			ID: uuid.NewString(), AssetID: assetID, TargetEntityID: target,
			TargetKind: "track", BindingRole: "track_audio", CreatedBy: uuid.NewString(),
		}); err != nil {
			t.Fatalf("bind: %v", err)
		}
	}
	mkBind(oldAsset, oldID)
	mkBind(canonicalAsset, canonicalID)
	t.Cleanup(func() {
		bg := context.Background()
		_, _ = st.DB().ExecContext(bg, "DELETE FROM storage.bindings WHERE asset_id IN ($1,$2)", oldAsset, canonicalAsset)
		_, _ = st.DB().ExecContext(bg, "DELETE FROM storage.assets WHERE id IN ($1,$2)", oldAsset, canonicalAsset)
	})

	cat := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		entity := func(id string) map[string]any { return map[string]any{"id": id, "kind": "track"} }
		identity := func(canonical string, aliases []string) map[string]any {
			return map[string]any{"canonical_id": canonical, "aliases": aliases, "entity": entity(canonical)}
		}
		switch p {
		case "/api/catalog/entities/" + oldID:
			_ = json.NewEncoder(w).Encode(entity(oldID))
		case "/api/catalog/entities/" + canonicalID:
			_ = json.NewEncoder(w).Encode(entity(canonicalID))
		case "/api/catalog/entities/" + oldID + "/identity":
			_ = json.NewEncoder(w).Encode(identity(canonicalID, []string{oldID}))
		case "/api/catalog/entities/" + canonicalID + "/identity":
			_ = json.NewEncoder(w).Encode(identity(canonicalID, []string{}))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer cat.Close()

	gin.SetMode(gin.TestMode)
	r := gin.New()
	New(st, &objects.Store{}, catalog.New(cat.URL), newVerifier(t, "http://127.0.0.1:1/jwks"), config.Config{}).Register(r)
	getFiles := func(entityID string) []map[string]any {
		t.Helper()
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/storage/entities/"+entityID+"/files", nil))
		if w.Code != http.StatusOK {
			t.Fatalf("GET %s/files 返回 %d（%s）", entityID, w.Code, w.Body.String())
		}
		var out struct {
			Files []map[string]any `json:"files"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatalf("解析文件列表失败: %v", err)
		}
		return out.Files
	}
	assetsOf := func(files []map[string]any) (assets, bindings map[string]bool) {
		assets, bindings = map[string]bool{}, map[string]bool{}
		for _, f := range files {
			if id, _ := f["id"].(string); id != "" {
				if bindings[id] {
					t.Fatalf("绑定 %s 重复出现", id)
				}
				bindings[id] = true
			}
			if a, _ := f["asset"].(map[string]any); a != nil {
				if id, _ := a["id"].(string); id != "" {
					assets[id] = true
				}
			}
		}
		return assets, bindings
	}

	// 从旧 ID 读：旧绑定 + 存活身份上的绑定一次可见，且去重。
	assets, _ := assetsOf(getFiles(oldID))
	if !assets[oldAsset] || !assets[canonicalAsset] {
		t.Fatalf("从旧 ID 应聚合两 ID 的文件，实际资产 %v", assets)
	}

	// 从存活身份读：历史旧 ID 上的行仍不可见（待目录反向契约）。
	assets, _ = assetsOf(getFiles(canonicalID))
	if !assets[canonicalAsset] {
		t.Fatalf("存活身份自己的文件必须可见，实际资产 %v", assets)
	}
	if assets[oldAsset] {
		t.Fatalf("待反向全量：目录反向契约落地前，从存活身份不应看到历史旧 ID 的行（若此断言失败说明反向已可用，请升级实现并改断言）")
	}
}
