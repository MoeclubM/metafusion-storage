package auth

import "testing"

// 码名必须与账号服务的权限清单逐字一致（metafusion-auth/internal/store/access.go 的
// PermissionCatalog）：拼错一个字母就是「后台配了组、本服务不认」，而且不会有编译错误。
func TestPermissionCodesMatchAccountServiceManifest(t *testing.T) {
	cases := map[string]string{
		PermissionAssetUpload:   "storage.asset.upload",
		PermissionAssetModerate: "storage.asset.moderate",
	}
	for got, want := range cases {
		if got != want {
			t.Fatalf("权限码 %q 与账号服务清单 %q 不一致", got, want)
		}
	}
	if len(storagePermissionCodes) != 2 {
		t.Fatalf("本服务声明的存储码应为 2 个，实际 %d 个", len(storagePermissionCodes))
	}
}

// 放行：令牌带 permissions 时，持码即通过，不看角色与组名。
func TestCanGrantsWhenTokenCarriesCode(t *testing.T) {
	p := &Principal{
		ID: "u1", Role: "user",
		Groups:      []string{"storage_moderator"},
		Permissions: []string{"storage.asset.moderate"},
	}
	if !p.Can(PermissionAssetModerate) {
		t.Fatal("持有 storage.asset.moderate 的成员应可审核资源")
	}
	if p.Can(PermissionAssetUpload) {
		t.Fatal("只授予了审核码，不应连带放行上传码")
	}
}

// 拒绝：别的子系统的码在本服务不作数（权限码按服务归属，不跨服务生效）。
func TestCanDeniesUnrelatedCode(t *testing.T) {
	p := &Principal{ID: "u1", Role: "user", Permissions: []string{"community.post.create"}}
	if p.Can(PermissionAssetModerate) || p.Can(PermissionAssetUpload) {
		t.Fatal("论坛发帖码不应放行任何存储权限")
	}
}

// 通配符：admin 组的 * 号放行本服务全部码。
func TestCanGrantsWildcard(t *testing.T) {
	p := &Principal{ID: "u1", Role: "user", Permissions: []string{"*"}}
	for _, code := range storagePermissionCodes {
		if !p.Can(code) {
			t.Fatalf("* 应放行 %s", code)
		}
	}
}

// 兼容：老令牌（缺 permissions 键、非第三方、非 PAT）仅保留上传历史边界（S01 已关闭 admin 兜底）。
// S01 起审核码不再设 admin 兜底；上传码是收口前的“登录即可”，非 admin 角色仍可传（见 legacyOpenCodes）。
func TestCanFallsBackToRoleForLegacyToken(t *testing.T) {
	legacyAdmin := &Principal{ID: "u1", Role: "admin"}
	if !legacyAdmin.Can(PermissionAssetUpload) {
		t.Fatal("老令牌仍可上传：收口前上传只要求登录")
	}
	if legacyAdmin.Can(PermissionAssetModerate) {
		t.Fatal("S01 起老令牌的 admin 也不得凭角色放行审核码")
	}
	// 角色兜底只覆盖本服务声明的码，别的子系统的码不归存储判。
	if legacyAdmin.Can("catalog.entity.edit") {
		t.Fatal("历史兜底只认本服务声明的码，不应放行目录侧的码")
	}
	for _, role := range []string{"editor", "user", ""} {
		p := &Principal{ID: "u2", Role: role}
		if !p.Can(PermissionAssetUpload) {
			t.Fatalf("老令牌角色 %q 仍可上传（收口前只要求登录）", role)
		}
		if p.Can(PermissionAssetModerate) {
			t.Fatalf("老令牌角色 %q 不得放行审核码", role)
		}
	}
}

// S01：显式空权限（含空数组、PermissionsSet）不得回落 admin，即使角色是 admin。
func TestCanDeniesExplicitEmptyAdmin(t *testing.T) {
	explicitEmpty := &Principal{ID: "u-8", Role: "admin", Permissions: []string{}, PermissionsSet: true}
	for _, code := range storagePermissionCodes {
		if explicitEmpty.Can(code) {
			t.Fatalf("显式空权限不得回落 admin：%s 不该放行", code)
		}
	}
	nonNilEmpty := &Principal{ID: "u-9", Role: "admin", Permissions: []string{}}
	if nonNilEmpty.Can(PermissionAssetModerate) || nonNilEmpty.Can(PermissionAssetUpload) {
		t.Fatal("非 nil 空集合不得回落 admin")
	}
}

// S01：第三方 OAuth 身份在治理码上直接不放行；上传码仍以码为准（空即不放行）。
func TestCanDeniesThirdPartyGovernance(t *testing.T) {
	thirdPartyAdmin := &Principal{
		ID: "u-10", Role: "admin", Groups: []string{"admin"}, Permissions: []string{"*"},
		Scope: "openid profile", ClientID: "third-party-app", IsThirdParty: true, PermissionsSet: true,
	}
	if thirdPartyAdmin.Can(PermissionAssetModerate) {
		t.Fatal("第三方令牌不得放行审核码：即使带 * 通配")
	}
	thirdPartyUploader := &Principal{
		ID: "u-11", Role: "user", Permissions: []string{PermissionAssetUpload},
		Scope: "profile", ClientID: "third-party-app", IsThirdParty: true, PermissionsSet: true,
	}
	if !thirdPartyUploader.Can(PermissionAssetUpload) {
		t.Fatal("第三方令牌的上传码仍以码为准：持有即放行")
	}
	if thirdPartyUploader.Can(PermissionAssetModerate) {
		t.Fatal("第三方令牌未持有审核码不得放行")
	}
}

// 令牌带了 permissions 就不再按角色兜底：否则后台收回权限组后，
// role 仍是 admin 的账号可以绕过权限组（角色兜底会变成后门）。
func TestCanIgnoresRoleWhenPermissionsPresent(t *testing.T) {
	p := &Principal{ID: "u1", Role: "admin", Permissions: []string{"community.post.create"}}
	if p.Can(PermissionAssetModerate) {
		t.Fatal("权限声明存在时应以码为准，角色不得额外放行")
	}
}

// 匿名不放行（nil 安全：调用点不必先判空）。
func TestCanDeniesAnonymous(t *testing.T) {
	var p *Principal
	if p.Can(PermissionAssetModerate) || p.Can(PermissionAssetUpload) {
		t.Fatal("匿名不应有任何存储权限")
	}
}
