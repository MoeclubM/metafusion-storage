package auth

import (
	"crypto/rsa"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Verify 必须解析 token_use/scope/client_id 并标记第三方；缺少用途声明要拒收。
func TestVerifyMarksThirdPartyToken(t *testing.T) {
	key := jwksTestKey(t)
	kid := jwksTestKID(t, &key.PublicKey)
	var hits int64
	cur := key
	srv := jwksTestServer(t, &hits, func() *rsa.PrivateKey { return cur }, nil, 0)
	v := jwksTestVerifier(t, srv.URL)

	sign := func(extra map[string]any) string {
		claims := jwt.MapClaims{
			"sub":       "22222222-2222-2222-2222-222222222222",
			"token_use": TokenUseSession,
		}
		for k, val := range extra {
			claims[k] = val
		}
		claims["iss"] = jwksTestIssuer
		claims["aud"] = jwksTestAudience
		claims["exp"] = time.Now().Add(10 * time.Minute).Unix()
		claims["iat"] = time.Now().Unix()
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		token.Header["kid"] = kid
		signed, err := token.SignedString(key)
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		return signed
	}

	empty, err := v.Verify(sign(map[string]any{}))
	if err != nil {
		t.Fatalf("会话令牌验签失败: %v", err)
	}
	if empty.IsThirdParty {
		t.Fatalf("会话令牌不得标为第三方: %+v", empty)
	}
	if empty.Can(PermissionAssetUpload) || empty.Can(PermissionAssetModerate) {
		t.Fatal("空权限会话不得放行存储码")
	}

	oauth, err := v.Verify(sign(map[string]any{"role": "admin", "permissions": []string{}, "token_use": "oauth", "client_id": "app-1", "scope": "openid profile"}))
	if err != nil {
		t.Fatalf("第三方令牌验签失败: %v", err)
	}
	if !oauth.IsThirdParty {
		t.Fatalf("第三方令牌必须标记用途: %+v", oauth)
	}
	if oauth.Scope != "openid profile" || oauth.ClientID != "app-1" {
		t.Fatalf("第三方标记透传不符: %+v", oauth)
	}
	if oauth.Can(PermissionAssetModerate) || oauth.Can(PermissionAssetUpload) {
		t.Fatal("显式空权限的第三方令牌不得放行任何存储码")
	}

	star, err := v.Verify(sign(map[string]any{"role": "admin", "permissions": []string{"*"}, "token_use": "oauth", "client_id": "app-1"}))
	if err != nil {
		t.Fatalf("第三方通配令牌验签失败: %v", err)
	}
	if star.Can(PermissionAssetModerate) {
		t.Fatal("第三方令牌不得放行审核码：即使带 * 通配")
	}
	if !star.Can(PermissionAssetUpload) {
		t.Fatal("第三方令牌的上传码仍以码为准")
	}

	cid, err := v.Verify(sign(map[string]any{"cid": "app-2"}))
	if err != nil {
		t.Fatalf("cid 别名令牌验签失败: %v", err)
	}
	if cid.IsThirdParty || cid.ClientID != "" {
		t.Fatalf("cid 旧别名不应影响身份: %+v", cid)
	}

	session, err := v.Verify(sign(map[string]any{"role": "user", "permissions": []string{PermissionAssetModerate}}))
	if err != nil {
		t.Fatalf("会话令牌验签失败: %v", err)
	}
	if session.IsThirdParty {
		t.Fatalf("会话令牌判定不符: %+v", session)
	}
	if !session.Can(PermissionAssetModerate) {
		t.Fatal("会话令牌持码即放行")
	}
}

// S01 回归：账号服务 Sign 恒写 token_use=session（并清零 scope/client_id）的新会话
// JWT 不得被误判第三方——持治理码可审文件、持上传码可普通上传。旧实现把任意非空
// token_use 判第三方，导致新会话连资产管理/审核都被治理码拒绝。
func TestVerifySessionTokenUseIsFirstParty(t *testing.T) {
	key := jwksTestKey(t)
	kid := jwksTestKID(t, &key.PublicKey)
	var hits int64
	cur := key
	srv := jwksTestServer(t, &hits, func() *rsa.PrivateKey { return cur }, nil, 0)
	v := jwksTestVerifier(t, srv.URL)

	sign := func(extra map[string]any) string {
		claims := jwt.MapClaims{
			"sub":       "33333333-3333-3333-3333-333333333333",
			"token_use": TokenUseSession,
		}
		for k, val := range extra {
			claims[k] = val
		}
		claims["iss"] = jwksTestIssuer
		claims["aud"] = jwksTestAudience
		claims["exp"] = time.Now().Add(10 * time.Minute).Unix()
		claims["iat"] = time.Now().Unix()
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		token.Header["kid"] = kid
		signed, err := token.SignedString(key)
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		return signed
	}

	// 与账号服务 Sign 的真实输出同形：token_use=session、无 scope/client_id、带权限组。
	session, err := v.Verify(sign(map[string]any{
		"token_use":   TokenUseSession,
		"permissions": []string{PermissionAssetUpload, PermissionAssetModerate},
	}))
	if err != nil {
		t.Fatalf("新会话 JWT 验签失败: %v", err)
	}
	if session.IsThirdParty {
		t.Fatal("token_use=session 不得判为第三方")
	}
	if !session.Can(PermissionAssetModerate) {
		t.Fatal("新会话持审核码应可审文件（治理码拒绝只针对第三方）")
	}
	if !session.Can(PermissionAssetUpload) {
		t.Fatal("新会话持上传码应可普通上传")
	}

	// 未知用途 fail closed：不能把将来新增用途的令牌当成已知用途放行。
	if _, err := v.Verify(sign(map[string]any{
		"token_use":   "superuser",
		"permissions": []string{permissionWildcard},
	})); err == nil {
		t.Fatal("未知 token_use 必须拒收")
	}

	if _, err := v.Verify(sign(map[string]any{"token_use": ""})); err == nil {
		t.Fatal("缺少 token_use 必须拒收")
	}
}
