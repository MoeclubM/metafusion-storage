package objects

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/MoeclubM/metafusion-storage/internal/config"
)

// fakeS3 是只实现本服务真正用到的那几个动作的 S3 端点：
// 建桶探测、初始化分片、上传分片、合并分片、PUT、HEAD、GET。
// 它让"预签名直传 + 分片合并"这条**从未真实跑过**的链路可以在离线环境端到端验证——
// 客户端那一步由测试自己按预签名 URL 发 PUT 来模拟。
type fakeS3 struct {
	mu      sync.Mutex
	objects map[string][]byte
	parts   map[string]map[int][]byte
	nextID  int
	// 记录收到的请求，供断言签名 URL 是否真的被用上。
	puts int
	// bucketMissing 为真时 HEAD /<bucket> 返回 404，用于验证服务会自己建桶。
	bucketMissing bool
	// created 记录收到的建桶请求（PUT /<bucket>）。
	created int
}

func newFakeS3(t *testing.T) (*httptest.Server, *fakeS3) {
	t.Helper()
	f := &fakeS3{objects: map[string][]byte{}, parts: map[string]map[int][]byte{}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		path := strings.TrimPrefix(r.URL.Path, "/")
		bucket, key := path, ""
		if i := strings.Index(path, "/"); i >= 0 {
			bucket, key = path[:i], path[i+1:]
		}

		switch {
		case r.Method == http.MethodHead && key == "":
			if f.bucketMissing {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.WriteHeader(http.StatusOK) // 桶存在
		case r.Method == http.MethodPut && key == "":
			f.bucketMissing = false // 建桶：之后的存在性探测都应通过
			f.created++
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodGet && key == "":
			w.Header().Set("Content-Type", "application/xml")
			_, _ = w.Write([]byte("<LocationConstraint></LocationConstraint>"))
		case r.Method == http.MethodPost && r.URL.Query().Has("uploads"):
			f.nextID++
			id := fmt.Sprintf("upload-%d", f.nextID)
			f.parts[id] = map[int][]byte{}
			w.Header().Set("Content-Type", "application/xml")
			_, _ = w.Write([]byte("<InitiateMultipartUploadResult><Bucket>" + bucket + "</Bucket><Key>" + key + "</Key><UploadId>" + id + "</UploadId></InitiateMultipartUploadResult>"))
		case r.Method == http.MethodPut && r.URL.Query().Has("uploadId"):
			id := r.URL.Query().Get("uploadId")
			n, _ := strconv.Atoi(r.URL.Query().Get("partNumber"))
			body := readAll(r)
			if f.parts[id] == nil {
				f.parts[id] = map[int][]byte{}
			}
			f.parts[id][n] = body
			f.puts++
			w.Header().Set("ETag", quoteETag(body))
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodPost && r.URL.Query().Has("uploadId"):
			id := r.URL.Query().Get("uploadId")
			nums := []int{}
			for n := range f.parts[id] {
				nums = append(nums, n)
			}
			sort.Ints(nums)
			merged := []byte{}
			for _, n := range nums {
				merged = append(merged, f.parts[id][n]...)
			}
			f.objects[key] = merged
			delete(f.parts, id)
			w.Header().Set("Content-Type", "application/xml")
			_, _ = w.Write([]byte("<CompleteMultipartUploadResult><Location>/" + bucket + "/" + key + "</Location><Bucket>" + bucket + "</Bucket><Key>" + key + "</Key><ETag>" + quoteETag(merged) + "</ETag></CompleteMultipartUploadResult>"))
		case r.Method == http.MethodPut:
			body := readAll(r)
			if r.Header.Get("Content-Encoding") == "aws-chunked" || indexOf(body, []byte("chunk-signature=")) >= 0 {
				body = decodeAWSChunked(body)
			}
			f.objects[key] = body
			w.Header().Set("ETag", quoteETag(body))
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodHead:
			body, ok := f.objects[key]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			// minio 的 StatObject 会解析 Last-Modified，缺这个头会直接报解析失败。
			w.Header().Set("Content-Length", strconv.Itoa(len(body)))
			w.Header().Set("ETag", quoteETag(body))
			w.Header().Set("Last-Modified", time.Now().UTC().Format(http.TimeFormat))
			w.Header().Set("Content-Type", "application/octet-stream")
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodGet:
			body, ok := f.objects[key]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Length", strconv.Itoa(len(body)))
			w.Header().Set("Last-Modified", time.Now().UTC().Format(http.TimeFormat))
			w.Header().Set("Content-Type", "application/octet-stream")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(body)
		default:
			w.WriteHeader(http.StatusNotImplemented)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, f
}

// decodeAWSChunked 还原 minio 客户端在签名 PUT 时使用的 aws-chunked 分块编码：
// 每块形如 "<十六进制长度>;chunk-signature=<sig>\r\n<数据>\r\n"，以 0 长度块结束。
// 真实 S3 会自行解码，这里的假端点必须自己处理，否则存下来的是带签名头的原始字节。
func decodeAWSChunked(body []byte) []byte {
	out := []byte{}
	rest := body
	for {
		i := indexOf(rest, []byte("\r\n"))
		if i < 0 {
			return out
		}
		header := string(rest[:i])
		sizeHex := header
		if j := indexOf([]byte(header), []byte(";")); j >= 0 {
			sizeHex = header[:j]
		}
		size, err := strconv.ParseInt(strings.TrimSpace(sizeHex), 16, 64)
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
		// 跳过块尾 CRLF
		if k := indexOf(rest, []byte("\r\n")); k == 0 {
			rest = rest[2:]
		}
	}
}

func indexOf(haystack, needle []byte) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		match := true
		for j := range needle {
			if haystack[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

func readAll(r *http.Request) []byte {
	defer r.Body.Close()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil
	}
	return body
}

func quoteETag(body []byte) string {
	sum := md5.Sum(body)
	return `"` + hex.EncodeToString(sum[:]) + `"`
}

// 桶不存在时由服务自己创建：这是"一条命令部署"能跑通的前提，
// 也替代了原先依赖 minio/mc 镜像的一次性初始化容器（该镜像已从 Docker Hub 撤下）。
func TestBucketBootstrappedWhenMissing(t *testing.T) {
	srv, fake := newFakeS3(t)
	fake.bucketMissing = true
	s := newStoreAgainst(t, srv.URL)
	if s.bucket != "metafusion-test" {
		t.Fatalf("bucket = %q", s.bucket)
	}
	if fake.created != 1 {
		t.Fatalf("应恰好发起一次建桶请求，实际 %d", fake.created)
	}
	if s.Local() {
		t.Fatal("配置了 S3 端点时不应是本地模式")
	}
}

// 桶已存在时不得重复建桶（否则每次启动都会多一次写请求，且并发启动会互相干扰）。
func TestBucketNotRecreatedWhenPresent(t *testing.T) {
	srv, fake := newFakeS3(t)
	_ = newStoreAgainst(t, srv.URL)
	if fake.created != 0 {
		t.Fatalf("桶已存在时不应建桶，实际发起 %d 次", fake.created)
	}
}

func newStoreAgainst(t *testing.T, endpoint string) *Store {
	t.Helper()
	cfg := config.Config{
		Root:             t.TempDir(),
		S3Endpoint:       endpoint,
		S3PublicEndpoint: endpoint,
		S3AccessKey:      "test-key",
		S3SecretKey:      "test-secret",
		S3Bucket:         "metafusion-test",
		S3TLS:            false,
		PresignTTL:       5 * time.Minute,
	}
	s, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("objects.New: %v", err)
	}
	if s.Local() {
		t.Fatal("配置了 S3 端点时不应是本地模式")
	}
	return s
}

// 分片直传的完整链路：建会话 → 逐片签发预签名 URL → 客户端 PUT → 合并 → 回读校验。
// 这是存储服务里最新、也最缺验证的一段代码（单体原本只做服务端中转上传）。
func TestMultipartPresignedUploadAgainstFakeS3(t *testing.T) {
	srv, fake := newFakeS3(t)
	s := newStoreAgainst(t, strings.TrimPrefix(srv.URL, "http://"))
	ctx := context.Background()

	part1, part2 := []byte("first-part-"), []byte("second-part")
	content := append(append([]byte{}, part1...), part2...)
	key := s.KeyFor("deadbeef", "track.flac")

	uploadID, err := s.NewParts(ctx, key, "audio/flac", 2)
	if err != nil || uploadID == "" {
		t.Fatalf("NewParts: id=%q err=%v", uploadID, err)
	}
	urls, err := s.PresignParts(ctx, key, "audio/flac", 2, uploadID)
	if err != nil || len(urls) != 2 {
		t.Fatalf("PresignParts: %d 个地址, err=%v", len(urls), err)
	}
	if !strings.Contains(urls[0], "uploadId="+uploadID) || !strings.Contains(urls[0], "partNumber=1") {
		t.Fatalf("预签名 URL 缺少分片参数: %s", urls[0])
	}

	// 模拟客户端直传：按预签名 URL 原样 PUT（不做任何额外签名）。
	for i, body := range [][]byte{part1, part2} {
		req, err := http.NewRequest(http.MethodPut, urls[i], strings.NewReader(string(body)))
		if err != nil {
			t.Fatalf("build put: %v", err)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("直传第 %d 片失败: %v", i+1, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("直传第 %d 片返回 %d", i+1, resp.StatusCode)
		}
	}
	if fake.puts != 2 {
		t.Fatalf("服务端应收到 2 次分片 PUT，实际 %d", fake.puts)
	}

	// 合并（ETag 由客户端从 PUT 响应头取回后回传）。
	parts := []Part{{PartNumber: 1, ETag: quoteETag(part1)}, {PartNumber: 2, ETag: quoteETag(part2)}}
	size, err := s.CompleteUpload(ctx, key, uploadID, parts)
	if err != nil {
		t.Fatalf("CompleteUpload: %v", err)
	}
	if size != int64(len(content)) {
		t.Fatalf("合并后大小 = %d，期望 %d", size, len(content))
	}

	// 回读：内容与哈希都要对得上。
	digest, gotSize, err := s.HashOf(ctx, key)
	if err != nil || gotSize != int64(len(content)) {
		t.Fatalf("HashOf: size=%d err=%v", gotSize, err)
	}
	if want := sha256Hex(content); digest != want {
		t.Fatalf("内容哈希不符: %s != %s", digest, want)
	}
	obj, n, err := s.Open(ctx, key)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer obj.Close()
	if n != int64(len(content)) {
		t.Fatalf("Open 返回大小 %d", n)
	}
}

// 单次 PUT 上传（part_count=1）与服务端中转（PutStream）在 S3 模式下同样要能落库。
func TestSinglePartAndServerSideUploadAgainstFakeS3(t *testing.T) {
	srv, _ := newFakeS3(t)
	s := newStoreAgainst(t, strings.TrimPrefix(srv.URL, "http://"))
	ctx := context.Background()

	content := []byte("single-part-body")
	key := s.KeyFor(sha256Hex(content), "cover.jpg")
	urls, err := s.PresignParts(ctx, key, "image/jpeg", 1, "")
	if err != nil || len(urls) != 1 {
		t.Fatalf("单次上传应只签发一个地址: %v", err)
	}
	req, _ := http.NewRequest(http.MethodPut, urls[0], strings.NewReader(string(content)))
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("单次直传失败: %v / %v", err, resp)
	}
	resp.Body.Close()
	size, err := s.CompleteUpload(ctx, key, "", nil)
	if err != nil || size != int64(len(content)) {
		t.Fatalf("单次上传完成确认失败: size=%d err=%v", size, err)
	}

	// 服务端中转路径（本地模式的主要上传方式，在 S3 模式下是兜底）。
	key2 := s.KeyFor(sha256Hex([]byte("server-side")), "scan.png")
	written, digest, err := s.PutStream(ctx, key2, strings.NewReader("server-side"))
	if err != nil || written != int64(len("server-side")) {
		t.Fatalf("PutStream: size=%d err=%v", written, err)
	}
	if digest != sha256Hex([]byte("server-side")) {
		t.Fatalf("PutStream 摘要不符: %s", digest)
	}
	readBack, _, err := s.HashOf(ctx, key2)
	if err != nil || readBack != digest {
		t.Fatalf("PutStream 后回读不符: %s err=%v", readBack, err)
	}
}
