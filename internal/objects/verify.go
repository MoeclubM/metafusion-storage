package objects

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"time"
)

// 预签名直传的对象从来没有经过服务端，initiate 采信的 sha256 只是客户端声明；
// 因此落定前必须由服务端把对象整份读回、重算摘要。否则"另一份等长内容"可以挂到
// 别人的 sha256 上，之后所有按该 sha256 秒传的人都会拿到错内容。
// verifyChunk 只决定回读时的内存占用，不整份读进内存。
const verifyChunk = 1 << 20

// ErrVerifyTooLarge 表示对象超过回读校验的大小上限（STORAGE_VERIFY_MAX_MB）。
var ErrVerifyTooLarge = errors.New("hash_verify_too_large")

// ErrVerifyTimeout 表示回读校验超过墙钟上限（STORAGE_VERIFY_TIMEOUT_SECONDS）。
var ErrVerifyTimeout = errors.New("verify_timeout")

// VerifyHash 把对象整份读回、重算 sha256，并在 expectedSHA256 非空时比对。
//
// 三条约束，顺序即优先级：
//  1. 先按对象元数据里的大小判上限：超限对象直接失败（ErrVerifyTooLarge），
//     不为了"先读一小段看看"而把不确定的大对象拖进校验流程；
//  2. 打开与读取共用同一个墙钟上限，任何一步超时都返回 ErrVerifyTimeout，
//     绝不返回半份摘要——半个摘要无法与"校验通过"区分，静默降级比显式失败更危险；
//  3. 只有完整读完才比对，不一致返回 ErrHashMismatch（内容寻址键被污染的信号）。
//
// 返回的 size 是实际回读字节数，失败路径上也返回已读到的部分，供调用方落库与排查。
func (s *Store) VerifyHash(ctx context.Context, key, expectedSHA256 string) (string, int64, error) {
	// 客户端断开（请求 ctx 取消）与配置的墙钟上限是两回事，必须分别可观测：
	// 上限另起一个带截止时间的子 ctx，用 parent ctx 是否已取消来区分。
	// 上限必须覆盖 Open 本身——对象存储的读取实现在首次 Read 时就把整份响应收完，
	// 只在逐块读取上看时间会把超时判成"读完且通过"。
	readCtx := ctx
	if s.verifyTimeout > 0 {
		var cancel context.CancelFunc
		readCtx, cancel = context.WithTimeout(ctx, s.verifyTimeout)
		defer cancel()
	}

	// 打开失败也要按超时归类：超限对象本就该在读到一半前被拒绝，
	// 而不是因为"没读完"被误报成对象存储不可用。
	obj, size, err := s.Open(readCtx, key)
	if err != nil {
		if timeoutFrom(ctx, readCtx, err) {
			return "", 0, ErrVerifyTimeout
		}
		return "", 0, err
	}
	defer obj.Close()

	if s.verifyMaxBytes > 0 && size > s.verifyMaxBytes {
		return "", size, ErrVerifyTooLarge
	}

	hash := sha256.New()
	buf := make([]byte, verifyChunk)
	var read int64
	for {
		n, rerr := obj.Read(buf)
		if n > 0 {
			read += int64(n)
			if s.verifyMaxBytes > 0 && read > s.verifyMaxBytes {
				return "", read, ErrVerifyTooLarge
			}
			if _, werr := hash.Write(buf[:n]); werr != nil {
				return "", read, werr
			}
		}
		if rerr == nil {
			continue
		}
		if errors.Is(rerr, io.EOF) {
			break
		}
		if timeoutFrom(ctx, readCtx, rerr) {
			return "", read, ErrVerifyTimeout
		}
		return "", read, rerr
	}

	digest := hex.EncodeToString(hash.Sum(nil))
	if expectedSHA256 != "" && digest != expectedSHA256 {
		return digest, read, ErrHashMismatch
	}
	return digest, read, nil
}

// timeoutFrom 区分"到点"与"读失败"：请求 ctx 自己取消（客户端断开）不是超时，
// 只有配置上限派生的 readCtx 到期、或传输层回报超时，才算 ErrVerifyTimeout。
func timeoutFrom(parent, readCtx context.Context, readErr error) bool {
	if errors.Is(parent.Err(), context.Canceled) {
		return false
	}
	if errors.Is(readCtx.Err(), context.DeadlineExceeded) {
		return true
	}
	var netErr net.Error
	return errors.As(readErr, &netErr) && netErr.Timeout()
}

// VerifyTimeout 与 VerifyMaxBytes 暴露回读校验的两个上限（0 为不限制），
// 供启动日志与 README 的口径对齐。
func (s *Store) VerifyTimeout() time.Duration { return s.verifyTimeout }

func (s *Store) VerifyMaxBytes() int64 { return s.verifyMaxBytes }
