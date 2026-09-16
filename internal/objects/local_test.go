package objects

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/MoeclubM/metafusion-storage/internal/config"
)

// 本地对象模式（未配置 S3 端点）是开发与自测的默认路径：
// 直传走服务端流式接收，这里验证落盘、回读与哈希三条路。
func TestLocalObjectModeRoundTrip(t *testing.T) {
	s, err := New(context.Background(), config.Config{Root: t.TempDir(), S3Bucket: "unused", PresignTTL: time.Minute})
	if err != nil {
		t.Fatalf("objects.New: %v", err)
	}
	if !s.Local() {
		t.Fatal("未配置 S3 端点时必须走本地模式")
	}
	content := []byte("local-mode-body")
	key := s.KeyFor(sha256Hex(content), "local.flac")
	size, digest, err := s.PutStream(context.Background(), key, strings.NewReader(string(content)), sha256Hex(content))
	if err != nil || size != int64(len(content)) {
		t.Fatalf("PutStream: size=%d err=%v", size, err)
	}
	if digest != sha256Hex(content) {
		t.Fatalf("摘要不符: %s", digest)
	}
	// 本地模式没有预签名，直传端点应返回空地址由 HTTP 层改为服务端接收。
	if urls, err := s.PresignParts(context.Background(), key, "audio/flac", 3, "x"); err != nil || urls != nil {
		t.Fatalf("本地模式不应签发预签名地址: %v", urls)
	}
	back, gotSize, err := s.HashOf(context.Background(), key)
	if err != nil || back != digest || gotSize != size {
		t.Fatalf("回读不符: %s(%d) err=%v", back, gotSize, err)
	}
	// 同一内容重复写入应覆盖成功且内容一致（内容寻址下键相同）。
	if _, _, err = s.PutStream(context.Background(), key, strings.NewReader(string(content)), sha256Hex(content)); err != nil {
		t.Fatalf("重复写入失败: %v", err)
	}
	again, _, err := s.HashOf(context.Background(), key)
	if err != nil || again != digest {
		t.Fatalf("重复写入后内容变化: %s err=%v", again, err)
	}
}

// 声明摘要与实际内容不符时：不发布对象、不回读得到内容（内容寻址键不得被污染）。
func TestPutStreamRefusesHashMismatch(t *testing.T) {
	s, err := New(context.Background(), config.Config{Root: t.TempDir(), S3Bucket: "unused", PresignTTL: time.Minute})
	if err != nil {
		t.Fatalf("objects.New: %v", err)
	}
	content := []byte("actual-body")
	claimed := sha256Hex([]byte("some-other-body"))
	key := s.KeyFor(claimed, "poison.flac")
	size, digest, err := s.PutStream(context.Background(), key, strings.NewReader(string(content)), claimed)
	if !errors.Is(err, ErrHashMismatch) {
		t.Fatalf("摘要不符应返回 ErrHashMismatch，实际 err=%v", err)
	}
	if digest != sha256Hex(content) || size != int64(len(content)) {
		t.Fatalf("错误路径也要如实返回实际摘要/长度: %s(%d)", digest, size)
	}
	if _, _, err = s.HashOf(context.Background(), key); err == nil {
		t.Fatal("摘要不符时对象不得落在内容寻址键上")
	}
}
