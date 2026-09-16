package auth

// 存储侧授权的集中判定：以权限码为准，角色只在老令牌上兜底。
//
// 权限码由账号服务（metafusion-auth）装进权限组并随访问令牌的 `permissions` 声明
// 与 /api/auth/me 下发（admin 组带 `*` 通配）。码名必须与账号服务的权限清单逐字一致：
// metafusion-auth/internal/store/access.go 的 PermissionCatalog，
// 组→码的播种见同仓库 internal/store/seed_groups.go。两边都只读令牌、谁也不查对方的库，
// 唯一要对齐的就是码的拼写。
//
// 判定只看 Permissions 与 Role：Groups 是组码，用于排障与展示，不参与授权——
// 散落的组名/角色比较正是「后台分配了权限组、本服务却不认」的成因。
//
// 单一来源（进行中）：这几个码与账号服务的清单、以及其余子系统的码表，计划由 metafusion-sdk
// 统一提供（见主仓库 docs/architecture/decoupling-audit-2026-09.md §3）。本批次不引入依赖，
// 在此之前改动码表仍以 metafusion-auth 的 PermissionCatalog 为准。

const (
	// PermissionAssetUpload 上传资源：创建自己的资产、完成直传、绑定用途。
	//
	// 收口点：POST /upload/initiate、POST /upload/complete、PUT /upload/stream/:assetId、
	// POST /bind（handler 的 requireUpload 中间件）；缺码 403 forbidden，未登录 401。
	// 解绑、读接口与 /stats 不收此码：前者按上传者判定所有权，后者走 moderate 或匿名可见性。
	//
	// 与 moderate 的分工：本码是「创建并登记自己的东西」，moderate 是「处置他人的东西」
	// （续传/覆盖他人未完成上传、完成/绑定他人资产、读全局统计）。两者互不蕴含。
	//
	// 为什么可以收口：账号服务把本码播进 member 组（任何登录用户默认持有）并对存量实例做
	// 只增不改的回填，因此两侧同批上线后成员照常上传；实例要收紧时从 member 组移除该码即可，
	// 老令牌（无 permissions 声明）仍按历史角色兜底，不会因为升级突然失去上传能力。
	PermissionAssetUpload = "storage.asset.upload"

	// PermissionAssetModerate 审核资源：处置他人的资产（完成合并、流式接收、绑定、
	// 解绑、读取可见性直通）与全局统计。它精确对应拆分前「仅 role=admin 享有的额外权力」，
	// 因此原 IsAdmin 调用点全部换成本码，边界不放宽也不收紧。
	PermissionAssetModerate = "storage.asset.moderate"

	// permissionWildcard 是账号服务给的「全部权限」码（admin 组）。
	permissionWildcard = "*"
)

// storagePermissionCodes 是本服务声明的全部存储权限码：角色兜底只认这些码，
// 不会因为角色是 admin 就放行别的子系统的码（catalog.* / community.* / auth.* 归各自服务）。
var storagePermissionCodes = []string{PermissionAssetUpload, PermissionAssetModerate}

// Can 报告调用者是否持有某个权限码（匿名一律不放行）。
//
// 令牌带 permissions 时一律以码为准（`*` 通配即全权）：拆服务后这是唯一的授权来源，
// 此时角色不再额外放行，否则「角色兜底」会变成绕过权限组的后门——
// 管理员在后台收回权限组后，本服务必须跟着不认。
// 只有令牌完全没有 permissions 声明时（老令牌，或尚未按权限组配置的实例）才按历史角色兜底：
// admin 放行全部存储码，其余角色一律不放行；与拆分前「只有 admin 有额外权力」逐条对应。
func (p *Principal) Can(code string) bool {
	if p == nil {
		return false
	}
	if len(p.Permissions) > 0 {
		for _, granted := range p.Permissions {
			if granted == permissionWildcard || granted == code {
				return true
			}
		}
		return false
	}
	return p.Role == "admin" && containsCode(storagePermissionCodes, code)
}

// containsCode 只在本服务声明的码集合里做线性查找（两个码，不值得建 map）。
func containsCode(codes []string, code string) bool {
	for _, c := range codes {
		if c == code {
			return true
		}
	}
	return false
}
