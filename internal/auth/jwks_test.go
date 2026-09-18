package auth

// JWKS 的三条约束（2026-09-19 第二轮架构报告 #22）：
//  1. 刷新失败（账号服务抖动）时，缓存里仍然有效的旧键必须继续可用，不能直接 401；
//  2. 出站请求不持缓存锁，且并发未知 kid 共享同一次刷新（出站请求数有界）；
//  3. 缓存里没有该 kid 的键时仍然 fail closed。
//
// 用例自带一个"账号服务"（JWKS 端点 + 可开关的故障）与一个签发侧，不依赖真实账号服务。

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/MoeclubM/metafusion-storage/internal/config"
)

const (
	jwksTestIssuer   = "https://findverse.cc/api"
	jwksTestAudience = "metafusion"
)

func jwksTestKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("生成测试密钥: %v", err)
	}
	return key
}

func jwksTestKID(t *testing.T, key *rsa.PublicKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	sum := sha256.Sum256(der)
	return base64.RawURLEncoding.EncodeToString(sum[:8])
}

// jwksTestServer 起一个与账号服务同格式的 JWKS 端点，并统计出站请求次数；
// fail 为真时返回 500（模拟账号服务抖动），delay 用来拉长飞行窗口。
func jwksTestServer(t *testing.T, hits *int64, current func() *rsa.PrivateKey, fail *atomic.Bool, delay time.Duration) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(hits, 1)
		if delay > 0 {
			time.Sleep(delay)
		}
		if fail != nil && fail.Load() {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		pub := &current().PublicKey
		doc := map[string]any{"keys": []map[string]any{{
			"kty": "RSA", "use": "sig", "alg": "RS256", "kid": jwksTestKID(t, pub),
			"n": base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
		}}}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(doc)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func jwksTestVerifier(t *testing.T, url string) *Verifier {
	t.Helper()
	v, err := New(config.Config{JWKSURL: url, JWTIssuer: jwksTestIssuer, JWTAudience: jwksTestAudience})
	if err != nil {
		t.Fatalf("装配验签器: %v", err)
	}
	return v
}

func jwksTestToken(t *testing.T, key *rsa.PrivateKey, kid string) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub":                "11111111-1111-1111-1111-111111111111",
		"preferred_username": "kana",
		"role":               "user",
		"iss":                jwksTestIssuer,
		"aud":                jwksTestAudience,
		"exp":                time.Now().Add(10 * time.Minute).Unix(),
		"iat":                time.Now().Unix(),
		"jti":                "jwks-test",
	})
	token.Header["kid"] = kid
	signed, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("签令牌: %v", err)
	}
	return signed
}

// 账号服务抖动：刷新失败时不能把所有已签发的令牌判成 401，缓存里的旧键要继续可用。
func TestJWKSRefreshFailureFallsBackToCachedKey(t *testing.T) {
	key := jwksTestKey(t)
	var hits int64
	var down atomic.Bool
	cur := key
	srv := jwksTestServer(t, &hits, func() *rsa.PrivateKey { return cur }, &down, 0)
	v := jwksTestVerifier(t, srv.URL)

	token := jwksTestToken(t, key, jwksTestKID(t, &key.PublicKey))
	if _, err := v.Verify(token); err != nil {
		t.Fatalf("首次验签: %v", err)
	}
	if n := atomic.LoadInt64(&hits); n != 1 {
		t.Fatalf("首次验签应拉取一次 JWKS，实际 %d 次", n)
	}

	down.Store(true)
	v.mu.Lock()
	v.fetchedAt = time.Now().Add(-2 * keyCacheTTL)
	v.mu.Unlock()
	if _, err := v.Verify(token); err != nil {
		t.Fatalf("刷新失败时应回落到缓存公钥，实际被拒：%v", err)
	}
	if n := atomic.LoadInt64(&hits); n != 2 {
		t.Fatalf("缓存过期后应尝试刷新一次，实际累计 %d 次", n)
	}
	if _, err := v.Verify(jwksTestToken(t, jwksTestKey(t), "unknown-kid")); err == nil {
		t.Fatal("缓存里没有的 kid 即使 JWKS 挂掉也必须被拒")
	}

	down.Store(false)
	v.mu.Lock()
	v.fetchedAt = time.Now().Add(-2 * keyCacheTTL)
	v.mu.Unlock()
	if _, err := v.Verify(token); err != nil {
		t.Fatalf("JWKS 恢复后应重新刷新并通过: %v", err)
	}
}

// 并发未知 kid：出站请求必须共享同一次刷新（旧实现会在持锁期间每个请求刷两次）。
func TestJWKSConcurrentUnknownKidSharesOneFetch(t *testing.T) {
	keyA, keyB := jwksTestKey(t), jwksTestKey(t)
	var hits int64
	cur := keyA
	srv := jwksTestServer(t, &hits, func() *rsa.PrivateKey { return cur }, nil, 100*time.Millisecond)
	v := jwksTestVerifier(t, srv.URL)

	if _, err := v.Verify(jwksTestToken(t, keyA, jwksTestKID(t, &keyA.PublicKey))); err != nil {
		t.Fatalf("预热验签: %v", err)
	}
	warm := atomic.LoadInt64(&hits)

	const racers = 16
	tokenB := jwksTestToken(t, keyB, jwksTestKID(t, &keyB.PublicKey))
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, _ = v.Verify(tokenB)
		}()
	}
	close(start)
	wg.Wait()

	got := atomic.LoadInt64(&hits) - warm
	t.Logf("%d 个并发未知 kid 产生的出站请求数 = %d", racers, got)
	if got != 1 {
		t.Fatalf("并发未知 kid 应共享同一次刷新（出站请求数 1），实际 %d", got)
	}
}
