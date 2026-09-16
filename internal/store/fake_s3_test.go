package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/MoeclubM/metafusion-storage/internal/config"
	"github.com/MoeclubM/metafusion-storage/internal/objects"
	"github.com/MoeclubM/metafusion-storage/internal/testutil"
)

const fakeStoreBucket = "metafusion-test"

// TestVerifiedAssetByHashPreferringVerified 用真实 PostgreSQL + 假 S3 端点覆盖
// "预签名直传入库 + 查重只认已验内容"这条链路：内容不是服务端收的，
// 只有回读校验能证明键上的字节确实等于声明的 sha256。
func TestVerifiedAssetByHashPreferringVerified(t *testing.T) {
	db := testutil.Database(t)
	s, err := Open(context.Background(), testutil.DSN(t))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer s.Close()
	ctx := context.Background()
	if err = s.Init(ctx); err != nil {
		t.Fatalf("init schema: %v", err)
	}
	if _, err = db.ExecContext(ctx, "DELETE FROM storage.bindings"); err != nil {
		t.Fatalf("clean bindings: %v", err)
	}
	if _, err = db.ExecContext(ctx, "DELETE FROM storage.assets"); err != nil {
		t.Fatalf("clean assets: %v", err)
	}

	fake := newFakeStoreS3(t)
	objs, err := objects.New(ctx, config.Config{
		Root:             t.TempDir(),
		S3Endpoint:       fake.addr,
		S3PublicEndpoint: fake.addr,
		S3AccessKey:      "test-key",
		S3SecretKey:      "test-secret",
		S3Bucket:         fakeStoreBucket,
		PresignTTL:       5 * time.Minute,
	})
	if err != nil {
		t.Fatalf("objects.New: %v", err)
	}
	if objs.Local() {
		t.Fatal("配置了 S3 端点不应是本地模式")
	}

	// 两份内容逐字节等长、只有前缀不同：用例要证明的是"等长也拦得住"，
	// 长度通过截断同一份底稿保证，不靠人工数字符。
	base := []byte("correct-content-0123456789abcdef")
	correct := append([]byte{}, base...)
	wrong := append(append([]byte{}, []byte("WRONG!!")...), base[len("WRONG!!"):]...)
	if len(correct) != len(wrong) || string(correct) == string(wrong) {
		t.Fatalf("用例前提不成立：两份内容必须等长且不同（%d vs %d）", len(correct), len(wrong))
	}
	sha := sha256HexOf(correct)
	key := objs.KeyFor(sha, "track.flac")

	const uploader = "77777777-7777-7777-7777-777777777777"
	asset := Asset{
		ID:           uuid.NewString(),
		SHA256:       sha,
		DeclaredSize: int64(len(correct)),
		MimeType:     "audio/flac",
		FileName:     "track.flac",
		ObjectKey:    key,
		Status:       "pending",
		UploaderID:   uploader,
	}
	if err = s.CreateAsset(ctx, asset); err != nil {
		t.Fatalf("create asset: %v", err)
	}

	// 客户端直传把等长的错内容写到了该 sha256 的键上（预签名地址不会拦内容）。
	s3Put(t, objs, key, wrong)

	// 反证：只看大小的话这份对象"没问题"（declared_size 与实际一致），
	// 旧实现会据此把资产置为完成，从此所有按该 sha256 秒传的人都拿到错内容。
	if _, err := objs.CompleteUpload(ctx, key, "", nil); err != nil {
		t.Fatalf("CompleteUpload: %v", err)
	}
	digest, size, verr := objs.VerifyHash(ctx, key, asset.SHA256)
	if !errors.Is(verr, objects.ErrHashMismatch) {
		t.Fatalf("等长错内容应被判 hash_mismatch，实际 %v", verr)
	}
	if digest != sha256HexOf(wrong) || size != int64(len(wrong)) {
		t.Fatalf("校验失败也要如实返回实际摘要/长度: %s(%d)", digest, size)
	}

	// 校验没通过：不置完成、不记已验证、查重不命中。
	if err = s.CompleteAsset(ctx, asset.ID, size); !errors.Is(err, ErrAssetUnverified) {
		t.Fatalf("未验摘要不得置完成，实际 %v", err)
	}
	if _, err = s.VerifiedAssetByHash(ctx, sha); !errors.Is(err, ErrNotFound) {
		t.Fatalf("未验证资产不得被查重命中，实际 %v", err)
	}
	if err = s.MarkHashMismatch(ctx, asset.ID, "hash_mismatch"); err != nil {
		t.Fatalf("MarkHashMismatch: %v", err)
	}
	loaded, err := s.Asset(ctx, asset.ID)
	if err != nil || loaded.Status != "pending" || loaded.HashVerified || loaded.FailReason != "hash_mismatch" {
		t.Fatalf("失败态不符: %+v err=%v", loaded, err)
	}
	if _, err = s.VerifiedAssetByHash(ctx, sha); !errors.Is(err, ErrNotFound) {
		t.Fatalf("记了失败原因后仍不得被查重命中，实际 %v", err)
	}

	// 清掉污染对象后重传正确内容：校验通过 → 可被查重命中 → 置完成。
	if err = objs.Remove(ctx, key); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	s3Put(t, objs, key, correct)
	if _, gotSize, err := objs.VerifyHash(ctx, key, sha); err != nil || gotSize != int64(len(correct)) {
		t.Fatalf("正确内容应验通: size=%d err=%v", gotSize, err)
	}
	if err = s.MarkHashVerified(ctx, asset.ID, int64(len(correct))); err != nil {
		t.Fatalf("MarkHashVerified: %v", err)
	}
	if err = s.CompleteAsset(ctx, asset.ID, int64(len(correct))); err != nil {
		t.Fatalf("CompleteAsset: %v", err)
	}
	verified, err := s.VerifiedAssetByHash(ctx, sha)
	if err != nil || verified.ID != asset.ID || verified.Status != "complete" || !verified.HashVerified {
		t.Fatalf("验证通过的资产应可被查重命中: %+v err=%v", verified, err)
	}
}

func sha256HexOf(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// s3Put 按预签名地址把内容 PUT 上去，模拟客户端直传（假端点不校验签名，只处理路径）。
func s3Put(t *testing.T, objs *objects.Store, key string, content []byte) {
	t.Helper()
	urls, err := objs.PresignParts(context.Background(), key, "application/octet-stream", 1, "")
	if err != nil || len(urls) != 1 {
		t.Fatalf("PresignParts: %d 个地址, err=%v", len(urls), err)
	}
	req, err := http.NewRequest(http.MethodPut, urls[0], strings.NewReader(string(content)))
	if err != nil {
		t.Fatalf("build put: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("直传失败: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("直传返回 %d", resp.StatusCode)
	}
}

// fakeStoreS3 是 store 包用例用的最小 S3 端点：建桶探测、单次 PUT、HEAD、GET、DELETE。
type fakeStoreS3 struct {
	addr string
	srv  *httptest.Server
	mu   sync.Mutex
	objs map[string][]byte
}

func newFakeStoreS3(t *testing.T) *fakeStoreS3 {
	t.Helper()
	f := &fakeStoreS3{objs: map[string][]byte{}}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	f.addr = strings.TrimPrefix(f.srv.URL, "http://")
	return f
}

func (f *fakeStoreS3) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	path := strings.TrimPrefix(r.URL.Path, "/")
	key := ""
	if i := strings.Index(path, "/"); i >= 0 {
		key = path[i+1:]
	}
	switch {
	case r.Method == http.MethodHead && key == "":
		w.WriteHeader(http.StatusOK)
	case r.Method == http.MethodPut && key == "":
		w.WriteHeader(http.StatusOK)
	case r.Method == http.MethodGet && key == "":
		w.Header().Set("Content-Type", "application/xml")
		_, _ = w.Write([]byte("<LocationConstraint></LocationConstraint>"))
	case r.Method == http.MethodPut:
		f.objs[key] = decodeStoreChunked(readAllStore(r))
		w.WriteHeader(http.StatusOK)
	case r.Method == http.MethodDelete:
		delete(f.objs, key)
		w.WriteHeader(http.StatusNoContent)
	case r.Method == http.MethodHead:
		body, ok := f.objs[key]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.Header().Set("Last-Modified", time.Now().UTC().Format(http.TimeFormat))
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
	case r.Method == http.MethodGet:
		body, ok := f.objs[key]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.Header().Set("Last-Modified", time.Now().UTC().Format(http.TimeFormat))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	default:
		w.WriteHeader(http.StatusNotImplemented)
	}
}

func readAllStore(r *http.Request) []byte {
	defer r.Body.Close()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil
	}
	return body
}

// decodeStoreChunked 还原 aws-chunked 编码：签名 PUT 的分块是传输层细节，
// 真实 S3 自行解码，假端点必须自己处理，否则存下来的是带签名头的原始字节。
func decodeStoreChunked(body []byte) []byte {
	if !strings.Contains(string(body), "chunk-signature=") {
		return body
	}
	out := []byte{}
	rest := body
	for {
		i := strings.Index(string(rest), "\r\n")
		if i < 0 {
			return out
		}
		header := string(rest[:i])
		if j := strings.Index(header, ";"); j >= 0 {
			header = header[:j]
		}
		size, err := strconv.ParseInt(strings.TrimSpace(header), 16, 64)
		if err != nil {
			return append(out, rest...)
		}
		rest = rest[i+2:]
		if size == 0 {
			return out
		}
		if int64(len(rest)) < size {
			return append(out, rest...)
		}
		out = append(out, rest[:size]...)
		rest = rest[size:]
		if strings.HasPrefix(string(rest), "\r\n") {
			rest = rest[2:]
		}
	}
}
