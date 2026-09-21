package objects

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/minio/minio-go/v7"
)

// QuarantinePrefix 是隔离区前缀：对账发现的孤儿对象先搬到这里，再由运维确认删除。
// worker 只隔离不删除——"无引用"可能是扫描窗口期的中间态，删字节不可逆。
const QuarantinePrefix = "quarantine/"

// KeyPrefixFor 返回某 sha256 的对象键前缀：KeyFor 生成的键恒定落在这个前缀下。
// 双向核对的一半——键前缀与声明 sha 对不上，说明这行资产指向了别人的字节，
// 清理/对账都不得动它（只上报）。
func KeyPrefixFor(sha256hex string) string {
	prefix := sha256hex
	if len(prefix) > 2 {
		prefix = prefix[:2]
	}
	return "objects/" + prefix + "/" + sha256hex + "/"
}

// Exists 报告对象键上是否有字节：不存在与"读失败"是两种结论，调用方据此区分
// "内容丢了"与"对象存储不可用"，不可混成一个错误。
func (s *Store) Exists(ctx context.Context, key string) (bool, error) {
	if s.local {
		_, err := os.Stat(filepath.Join(s.root, filepath.FromSlash(key)))
		if err == nil {
			return true, nil
		}
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	_, err := s.client.StatObject(ctx, s.bucket, key, minio.StatObjectOptions{})
	if err == nil {
		return true, nil
	}
	if IsObjectMissing(err) {
		return false, nil
	}
	return false, err
}

// ListKeys 列出指定前缀下的对象键（slash 形式）：对账"对象→库"一半的输入。
// limit<=0 时默认上限 100000——全量列举是后台批处理的活，在线接口不调它。
func (s *Store) ListKeys(ctx context.Context, prefix string, limit int) ([]string, error) {
	if limit <= 0 {
		limit = 100000
	}
	if s.local {
		return s.listLocalKeys(prefix, limit)
	}
	out := []string{}
	opts := minio.ListObjectsOptions{Prefix: prefix, Recursive: true}
	for info := range s.client.ListObjects(ctx, s.bucket, opts) {
		if info.Err != nil {
			return nil, info.Err
		}
		out = append(out, info.Key)
		if len(out) >= limit {
			break
		}
	}
	return out, nil
}

func (s *Store) listLocalKeys(prefix string, limit int) ([]string, error) {
	out := []string{}
	err := filepath.WalkDir(s.root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, err := filepath.Rel(s.root, path)
		if err != nil {
			return err
		}
		key := filepath.ToSlash(rel)
		if prefix != "" && !strings.HasPrefix(key, prefix) {
			return nil
		}
		out = append(out, key)
		if len(out) >= limit {
			return errStopWalk
		}
		return nil
	})
	if errors.Is(err, errStopWalk) {
		err = nil
	}
	return out, err
}

var errStopWalk = errors.New("key limit reached")

// Quarantine 把对象搬进隔离区（quarantine/ 原键），返回隔离后的键。
// 本地模式是同盘 rename；对象存储模式是复制后删源键——删源失败则报脏状态
// （复制成功但源仍在），调用方不得记台账为已隔离，重试是幂等的。
func (s *Store) Quarantine(ctx context.Context, key string) (string, error) {
	if strings.HasPrefix(key, QuarantinePrefix) {
		return key, nil
	}
	dest := QuarantinePrefix + key
	if s.local {
		src := filepath.Join(s.root, filepath.FromSlash(key))
		dst := filepath.Join(s.root, filepath.FromSlash(dest))
		if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
			return "", err
		}
		if err := os.Rename(src, dst); err != nil {
			return "", err
		}
		return dest, nil
	}
	_, err := s.client.CopyObject(ctx,
		minio.CopyDestOptions{Bucket: s.bucket, Object: dest},
		minio.CopySrcOptions{Bucket: s.bucket, Object: key})
	if err != nil {
		return "", err
	}
	if err := s.client.RemoveObject(ctx, s.bucket, key, minio.RemoveObjectOptions{}); err != nil {
		return dest, err
	}
	return dest, nil
}
