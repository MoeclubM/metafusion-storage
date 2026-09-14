package objects

import (
	"crypto/sha256"
	"encoding/hex"
)

// sha256Hex 是测试用的摘要工具，与业务代码里的实现保持同一口径。
func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
