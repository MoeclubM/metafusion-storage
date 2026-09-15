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

// 老令牌兜底：没有 permissions 声明时，admin 仍可用；其余角色一律不放行
// （拆分前也只有 role == admin 有额外权力，兜底不得放宽边界）。
func TestCanFallsBackToRoleForLegacyToken(t *testing.T) {
	admin := &Principal{ID: "u1", Role: "admin"}
	for _, code := range storagePermissionCodes {
		if !admin.Can(code) {
			t.Fatalf("老管理员令牌应放行 %s", code)
		}
	}
	if admin.Can("catalog.entity.edit") {
		t.Fatal("角色兜底只认本服务声明的码，不应放行目录侧的码")
	}
	for _, role := range []string{"editor", "user", ""} {
		p := &Principal{ID: "u2", Role: role}
		if p.Can(PermissionAssetModerate) || p.Can(PermissionAssetUpload) {
			t.Fatalf("老令牌角色 %q 不应获得存储权限", role)
		}
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
