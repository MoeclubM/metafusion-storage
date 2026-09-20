package auth

// 存储侧授权的集中判定：以权限码为准（S01：显式空权限不回落 admin，治理 API 默认拒第三方）。
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
	// 老令牌（缺 permissions 键）按历史上传边界兼容（legacyOpenCodes），不会因为升级突然失去上传能力；
	// 显式空集合（PermissionsSet）不再回落，见 Can。
	PermissionAssetUpload = "storage.asset.upload"

	// PermissionAssetModerate 审核资源：处置他人的资产（完成合并、流式接收、绑定、
	// 解绑、读取可见性直通）与全局统计。它精确对应拆分前「仅 role=admin 享有的额外权力」，
	// 因此原 IsAdmin 调用点全部换成本码，边界不放宽也不收紧。
	PermissionAssetModerate = "storage.asset.moderate"

	// permissionWildcard 是账号服务给的「全部权限」码（admin 组）。
	permissionWildcard = "*"
)

// storagePermissionCodes 是本服务声明的全部存储权限码：历史兜底（仅 legacyOpenCodes）
// 不会因为角色是 admin 就放行别的子系统的码（catalog.* / community.* / auth.* 归各自服务）。
var storagePermissionCodes = []string{PermissionAssetUpload, PermissionAssetModerate}

// legacyOpenCodes 是老令牌（缺 permissions 键、非第三方、非 PAT）仍然放行的码。
//
// 只有上传码在这一列：在它成为闸门之前，上传**只要求登录**，任何已登录用户
// 都能传。账号服务尚未升级、令牌还不带 permissions 的实例如果按“角色兜底只认 admin”处理，
// 就会变成“除了管理员谁都不能上传”——那是把兼容策略做成了故障。
// 审核码不在此列：S01 起不再设 admin 角色兜底——会话登录令牌本就带权限组，
// 老 JWT 窗口最长 15 分钟，续期/兜底都会补齐权限。
var legacyOpenCodes = []string{PermissionAssetUpload}

// HasPermission 是**纯权限码集合判定**：只看 permissions 里的码（* 通配即全权），
// 不做任何角色兜底。PAT 身份（FromPAT）一律走它——PAT 的权限集合可能为空
// （scopes 里没有本服务的任何码），空集合必须表现为"什么都不许"，而不是回落到角色上拿权。
func (p *Principal) HasPermission(code string) bool {
	if p == nil {
		return false
	}
	for _, granted := range p.Permissions {
		if granted == permissionWildcard || granted == code {
			return true
		}
	}
	return false
}

// Can 报告调用者是否持有某个权限码（匿名一律不放行）。
//
// 令牌带 permissions 时一律以码为准（`*` 通配即全权）：拆服务后这是唯一的授权来源，
// 此时角色不再额外放行，否则「角色兜底」会变成绕过权限组的后门——
// 管理员在后台收回权限组后，本服务必须跟着不认。
// 只有令牌完全没有 permissions 声明时（缺 permissions 键的老令牌，或尚未按权限组配置的实例）
// 才按历史上传边界兜底：上传码见 legacyOpenCodes（收口前就是“登录即可”）；审核码不再设 admin 兜底。
//
// FromPAT（身份来自 PAT 内省）时**永不**回落到角色兜底：PAT 的权限就是账号服务算好的
// "用户自身权限 ∩ scopes"，scopes 空时就是空。若把它当"没有 permissions 声明"处理，
// 一个 scopes=[] 的管理员 PAT 会因为角色兜底拿到全部存储权限——收窄 scopes 也就形同虚设。
func (p *Principal) Can(code string) bool {
	if p == nil {
		return false
	}
	if p.IsThirdParty && isGovernanceCode(code) {
		return false
	}
	if p.PermissionsSet || p.Permissions != nil || len(p.Permissions) > 0 || p.FromPAT || p.IsThirdParty {
		return p.HasPermission(code)
	}
	return containsCode(legacyOpenCodes, code)
}

// isGovernanceCode 报告是否为治理类（管理）权限码：上传（storage.asset.upload）是用户
// 行为，不在此列；其余本服务声明的码都是管理动作，第三方令牌默认拒绝。
func isGovernanceCode(code string) bool {
	if code == PermissionAssetUpload {
		return false
	}
	return containsCode(storagePermissionCodes, code)
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
