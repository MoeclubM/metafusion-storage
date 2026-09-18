package objects

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"testing"

	"github.com/minio/minio-go/v7"

	"github.com/MoeclubM/metafusion-storage/internal/config"
)

// 读失败必须分成两类结论：键上没有对象（数据缺失，重试无意义）与对象存储不可用
// （503，值得重试）。混成一类时，"这批内容早就不在了"在响应与监控里与"对象存储挂了"
// 完全同形——线上自托管封面就是这样：元数据 200、内容稳定 503。
func TestIsObjectMissing(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"没有错误", nil, false},
		{"本地模式缺文件", &fs.PathError{Op: "open", Path: "objects/ab/x.png", Err: os.ErrNotExist}, true},
		{"包裹的缺文件", fmt.Errorf("打开对象失败: %w", os.ErrNotExist), true},
		{"S3 键不存在", minio.ErrorResponse{Code: "NoSuchKey", Message: "The specified key does not exist."}, true},
		{"S3 对象不存在", minio.ErrorResponse{Code: "NoSuchObject"}, true},
		// 桶不存在、凭据/签名错误都是部署问题：它们不是数据缺失，按 503 报才不会被当成"内容已丢"。
		{"桶不存在不是数据缺失", minio.ErrorResponse{Code: "NoSuchBucket"}, false},
		{"拒绝访问不是数据缺失", minio.ErrorResponse{Code: "AccessDenied"}, false},
		{"签名不符不是数据缺失", minio.ErrorResponse{Code: "SignatureDoesNotMatch"}, false},
		{"断网不是数据缺失", &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connection refused")}, false},
		{"普通错误不是数据缺失", errors.New("boom"), false},
	}
	for _, tc := range cases {
		if got := IsObjectMissing(tc.err); got != tc.want {
			t.Fatalf("%s: IsObjectMissing = %v，期望 %v", tc.name, got, tc.want)
		}
	}
}

// 对象模式是隐式的（端点为空即本地），所以"配了凭据却没配端点"必须启动失败：
// 静默回落到本地卷会让服务照常启动、只有读旧对象时才暴露，且现象和对象存储故障同形。
func TestNewRefusesAmbiguousObjectMode(t *testing.T) {
	if _, err := New(context.Background(), config.Config{
		Root: t.TempDir(), S3Bucket: "metafusion-master", S3AccessKey: "k", S3SecretKey: "s",
	}); err == nil {
		t.Fatal("端点为空但有凭据时应启动失败")
	}
	// 端点与凭据都没有仍是合法的本地对象模式：没有 RustFS 也要能开发与自测。
	s, err := New(context.Background(), config.Config{Root: t.TempDir(), S3Bucket: "metafusion-master"})
	if err != nil {
		t.Fatalf("纯本地模式应可用: %v", err)
	}
	if !s.Local() {
		t.Fatal("端点与凭据都为空时应是本地对象模式")
	}
}
