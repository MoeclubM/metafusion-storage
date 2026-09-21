package auth

import (
	"crypto/rsa"
	"encoding/json"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// S01：Verify 不能只验 iss/aud，必须解析 token_use/scope/client_id 并标记第三方；
// 载荷里 permissions 键是否存在决定“显式空”还是“老令牌”，两者走不同分支。
func TestVerifyMarksThirdPartyToken(t *testing.T) {
	key := jwksTestKey(t)
	kid := jwksTestKID(t, &key.PublicKey)
	var hits int64
	cur := key
	srv := jwksTestServer(t, &hits, func() *rsa.PrivateKey { return cur }, nil, 0)
	v := jwksTestVerifier(t, srv.URL)

	sign := func(extra map[string]any) string {
		claims := jwt.MapClaims{
			"sub":  "22222222-2222-2222-2222-222222222222",
			"role": "user",
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

	legacy, err := v.Verify(sign(map[string]any{}))
	if err != nil {
		t.Fatalf("老令牌验签失败: %v", err)
	}
	if legacy.IsThirdParty || legacy.PermissionsSet {
		t.Fatalf("无标记令牌不得标第三方/显式权限: %+v", legacy)
	}
	if !legacy.Can(PermissionAssetUpload) || legacy.Can(PermissionAssetModerate) {
		t.Fatal("老令牌仅保留历史上传边界")
	}

	oauth, err := v.Verify(sign(map[string]any{"role": "admin", "permissions": []string{}, "token_use": "oauth", "client_id": "app-1", "scope": "openid profile"}))
	if err != nil {
		t.Fatalf("第三方令牌验签失败: %v", err)
	}
	if !oauth.IsThirdParty || !oauth.PermissionsSet {
		t.Fatalf("第三方令牌必须标记用途与显式权限: %+v", oauth)
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
	if !cid.IsThirdParty || cid.ClientID != "app-2" {
		t.Fatalf("cid 应视为 client_id 别名: %+v", cid)
	}

	session, err := v.Verify(sign(map[string]any{"role": "user", "permissions": []string{PermissionAssetModerate}}))
	if err != nil {
		t.Fatalf("会话令牌验签失败: %v", err)
	}
	if session.IsThirdParty || !session.PermissionsSet {
		t.Fatalf("无标记的会话令牌判定不符: %+v", session)
	}
	if !session.Can(PermissionAssetModerate) {
		t.Fatal("会话令牌持码即放行")
	}
}

// claims 必须区分“缺 permissions 键”与“显式空数组”：两者解成的 Permissions 都是 len 0，
// 但 S01 要求前者走历史上传边界、后者以码为准（不回落 admin）。
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
			"sub":  "33333333-3333-3333-3333-333333333333",
			"role": "user",
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

	// 缺省用途下仍带 scope/client_id（签发侧过渡态）：视为第三方。
	transitional, err := v.Verify(sign(map[string]any{
		"scope":     "profile",
		"client_id": "transitional-app",
	}))
	if err != nil {
		t.Fatalf("过渡态令牌验签失败: %v", err)
	}
	if !transitional.IsThirdParty {
		t.Fatal("缺省用途下带 scope/client_id 必须判为第三方")
	}
}

func TestClaimsDistinguishesMissingVsEmptyPermissions(t *testing.T) {
	var missing claims
	if err := json.Unmarshal([]byte("{\"sub\":\"x\"}"), &missing); err != nil || missing.permissionsPresent {
		t.Fatalf("缺字段应记为非显式：%v %+v", err, missing)
	}
	var empty claims
	if err := json.Unmarshal([]byte("{\"sub\":\"x\",\"permissions\":[]}"), &empty); err != nil || !empty.permissionsPresent {
		t.Fatalf("显式空数组应记为显式：%v %+v", err, empty)
	}
	var full claims
	if err := json.Unmarshal([]byte("{\"sub\":\"x\",\"permissions\":[\"storage.asset.upload\"]}"), &full); err != nil || !full.permissionsPresent || len(full.Permissions) != 1 {
		t.Fatalf("持码载荷解析不符：%v %+v", err, full)
	}
}
