package objects

import (
	"context"
	"errors"
	"math/rand"
	"net/http"
	"strings"
	"testing"
	"time"
)

// 预签名直传的正确内容：合并后回读重算的摘要必须与声明一致，
// 这是 complete 允许把资产置为完成的唯一依据。
func TestVerifyHashAcceptsDeclaredContent(t *testing.T) {
	srv, _ := newFakeS3(t)
	s := newStoreAgainst(t, strings.TrimPrefix(srv.URL, "http://"))
	ctx := context.Background()

	content := []byte("correct-content-0123456789")
	digest := sha256Hex(content)
	key := s.KeyFor(digest, "track.flac")
	presignAndPut(t, s, key, content)

	if _, err := s.CompleteUpload(ctx, key, "", nil); err != nil {
		t.Fatalf("CompleteUpload: %v", err)
	}
	got, size, err := s.VerifyHash(ctx, key, digest)
	if err != nil {
		t.Fatalf("回读校验应通过: %v", err)
	}
	if got != digest || size != int64(len(content)) {
		t.Fatalf("回读结果 = %s(%d)，期望 %s(%d)", got, size, digest, len(content))
	}
}

// 反证：等长的错内容在**只看大小**的旧路径下会被判为"完成"。
// 这条用例固定住"大小一致 ≠ 内容一致"这个前提，也是生产故障的复现：
// 声明 sha256 与其长度的人，把另一份同样长度的内容挂上去即可污染该 sha256。
func TestVerifyHashRejectsEqualLengthMismatch(t *testing.T) {
	srv, _ := newFakeS3(t)
	s := newStoreAgainst(t, strings.TrimPrefix(srv.URL, "http://"))
	ctx := context.Background()

	correct := []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	wrong := []byte("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb") // 与 correct 等长
	declared := sha256Hex(correct)
	key := s.KeyFor(declared, "track.flac")
	presignAndPut(t, s, key, wrong)

	// 旧路径：HEAD 回读的大小与声明一致，size_mismatch 不会触发。
	size, err := s.CompleteUpload(ctx, key, "", nil)
	if err != nil {
		t.Fatalf("CompleteUpload: %v", err)
	}
	if size != int64(len(wrong)) {
		t.Fatalf("回读大小 = %d，期望 %d", size, len(wrong))
	}
	if size != int64(len(correct)) {
		t.Fatal("用例前提不成立：两份内容必须等长")
	}

	// 新路径：重算摘要并比对，必须失败。
	digest, read, err := s.VerifyHash(ctx, key, declared)
	if !errors.Is(err, ErrHashMismatch) {
		t.Fatalf("等长错内容应返回 ErrHashMismatch，实际 %v", err)
	}
	if digest != sha256Hex(wrong) || read != int64(len(wrong)) {
		t.Fatalf("失败路径也要如实返回实际摘要/长度: %s(%d)", digest, read)
	}
}

// 未验证的对象被清掉之后，同一个内容寻址键可以重新写入正确内容：
// 失败上传不会把这个 sha256 永久占住。
func TestRemoveClearsPollutedKey(t *testing.T) {
	srv, fake := newFakeS3(t)
	s := newStoreAgainst(t, strings.TrimPrefix(srv.URL, "http://"))
	ctx := context.Background()

	correct := []byte("the-real-content")
	declared := sha256Hex(correct)
	key := s.KeyFor(declared, "scan.png")
	presignAndPut(t, s, key, []byte("poisoned-content"))

	if _, _, err := s.VerifyHash(ctx, key, declared); !errors.Is(err, ErrHashMismatch) {
		t.Fatalf("污染内容应先被拒: %v", err)
	}
	if err := s.Remove(ctx, key); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	fake.mu.Lock()
	_, leaked := fake.objects[key]
	fake.mu.Unlock()
	if leaked {
		t.Fatal("校验失败的键上不得留下对象")
	}
	if _, _, err := s.VerifyHash(ctx, key, declared); err == nil {
		t.Fatal("删除后不该还能读回内容")
	}

	// 重传正确内容后校验通过，键可再次使用。
	presignAndPut(t, s, key, correct)
	if _, _, err := s.VerifyHash(ctx, key, declared); err != nil {
		t.Fatalf("重传正确内容后应通过: %v", err)
	}
	if err := s.Remove(ctx, key); err != nil {
		t.Fatalf("重复删除（不存在）应幂等: %v", err)
	}
}

// 超限对象必须显式失败：回读校验有成本，超过上限就不读，也不允许"跳过校验但置完成"。
func TestVerifyHashRefusesOversizedObject(t *testing.T) {
	srv, _ := newFakeS3(t)
	s := newStoreWithLimits(t, strings.TrimPrefix(srv.URL, "http://"), 1, 0) // 上限 1MiB
	ctx := context.Background()

	big := make([]byte, 2<<20)
	for i := range big {
		big[i] = byte(i)
	}
	digest := sha256Hex(big)
	key := s.KeyFor(digest, "disc.iso")
	presignAndPut(t, s, key, big)

	if _, size, err := s.VerifyHash(ctx, key, digest); !errors.Is(err, ErrVerifyTooLarge) {
		t.Fatalf("超限对象应返回 ErrVerifyTooLarge，实际 err=%v size=%d", err, size)
	}
	// 上限只拦回读校验，不影响对象本身可用；服务端明确失败而不是静默通过。
	if _, _, err := s.VerifyHash(ctx, key, ""); !errors.Is(err, ErrVerifyTooLarge) {
		t.Fatalf("不带声明也必须超限失败: %v", err)
	}
}

// 回读超时必须显式失败，且不返回半份摘要：半个摘要无法与"校验通过"区分。
func TestVerifyHashTimesOut(t *testing.T) {
	srv, fake := newFakeS3(t)
	fake.getDelay = 3 * time.Millisecond
	s := newStoreWithLimits(t, strings.TrimPrefix(srv.URL, "http://"), 0, 30*time.Millisecond)
	ctx := context.Background()

	// 内容必须是随机的：全零之类的可压缩数据会被传输层压成一个块，
	// 分块延迟就失效了，超时路径也就测不到。
	content := make([]byte, 8<<20)
	rng := rand.New(rand.NewSource(1))
	for i := range content {
		content[i] = byte(rng.Intn(256))
	}
	digest := sha256Hex(content)
	key := s.KeyFor(digest, "huge.flac")
	presignAndPut(t, s, key, content)

	got, read, err := s.VerifyHash(ctx, key, digest)
	if !errors.Is(err, ErrVerifyTimeout) {
		t.Fatalf("超时应返回 ErrVerifyTimeout，实际 err=%v", err)
	}
	if got != "" {
		t.Fatalf("超时不得返回摘要: %q", got)
	}
	if read >= int64(len(content)) {
		t.Fatalf("超时应在读完之前出现，已读 %d 字节", read)
	}

	// 对照组：同一份对象在足够宽的上限下必须能验通——
	// 失败是因为上限，而不是因为读不回来（否则这条用例会掩盖真实读取故障）。
	lenient := newStoreWithLimits(t, strings.TrimPrefix(srv.URL, "http://"), 0, time.Minute)
	if _, size, err := lenient.VerifyHash(ctx, key, digest); err != nil || size != int64(len(content)) {
		t.Fatalf("宽上限下应验通: size=%d err=%v", size, err)
	}
}

// 请求 ctx 自己取消（客户端断开）不能被说成配置的墙钟上限。
func TestVerifyHashDistinguishesCancelFromTimeout(t *testing.T) {
	srv, _ := newFakeS3(t)
	s := newStoreWithLimits(t, strings.TrimPrefix(srv.URL, "http://"), 0, 5*time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	content := []byte("cancel-me")
	digest := sha256Hex(content)
	key := s.KeyFor(digest, "cancel.bin")
	presignAndPut(t, s, key, content)
	cancel()

	if _, _, err := s.VerifyHash(ctx, key, digest); err == nil || errors.Is(err, ErrVerifyTimeout) {
		t.Fatalf("ctx 取消除非超时: err=%v", err)
	}
}

// presignAndPut 按预签名地址把内容 PUT 上去，模拟客户端直传。
func presignAndPut(t *testing.T, s *Store, key string, content []byte) {
	t.Helper()
	urls, err := s.PresignParts(context.Background(), key, "application/octet-stream", 1, "")
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
