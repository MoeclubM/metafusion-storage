"use client";

// 会话与权限：同域 cookie（账号服务签发），前端同源请求 /api/auth/me 拿当前用户与 permissions。
// 这里只做"界面收敛"，不替代服务端鉴权——真正的闸门在存储服务的 requireUpload 与各 handler 里。

export const LOGIN_PATH = process.env.NEXT_PUBLIC_LOGIN_PATH || "/login";

export type SessionUser = {
  id: string;
  username: string;
  email?: string;
  role: string;
  groups?: string[];
  permissions?: string[];
  banned?: boolean;
};

export const PERMISSION_ASSET_UPLOAD = "storage.asset.upload";
export const PERMISSION_ASSET_MODERATE = "storage.asset.moderate";

// 与 internal/auth/permission.go 的 storagePermissionCodes 逐字一致。
const STORAGE_PERMISSION_CODES = [PERMISSION_ASSET_UPLOAD, PERMISSION_ASSET_MODERATE];

/**
 * 镜像服务端的授权判定（internal/auth/permission.go 的 Principal.Can）：
 *   - 身份带 permissions 时一律以码为准（"*" 即全权），此时角色不再额外放行；
 *   - 只有完全没有 permissions 声明时（老令牌，或尚未按权限组配置的实例）才按历史角色兜底：
 *     admin 放行本服务全部码，其余角色不放行。
 * 前端多认一条或少认一条都会造成"界面给了按钮、点了必然 403"或"该看到却被藏起来"，所以口径必须逐条对齐。
 */
export function can(user: SessionUser | null, code: string): boolean {
  if (!user) return false;
  const perms = user.permissions ?? [];
  if (perms.length > 0) {
    return perms.some((p) => p === "*" || p === code);
  }
  return user.role === "admin" && STORAGE_PERMISSION_CODES.includes(code);
}

/** /api/auth/me：未登录是 401 authentication_required，null 表示"需要去登录"。 */
export async function fetchSession(): Promise<SessionUser | null> {
  let res: Response;
  try {
    res = await fetch("/api/auth/me", { cache: "no-store", credentials: "include" });
  } catch (err) {
    throw new Error(err instanceof Error ? err.message : String(err));
  }
  if (res.status === 401) return null;
  if (!res.ok) throw new Error("HTTP " + res.status);
  return (await res.json()) as SessionUser;
}

/** 登录页在主站（同域根路径），带上回跳地址：登录后回到管理台当前页面。 */
export function loginRedirectUrl(): string {
  if (typeof window === "undefined") return LOGIN_PATH;
  const here = window.location.pathname + window.location.search;
  // 已经在登录页上就不要再套一层 redirect：那一层会被下一次渲染当成"当前地址"再编码一次，
  // 于是 redirect 无限套娃（浏览器地址栏越滚越长，用户看到的是反复跳转）。
  if (here === LOGIN_PATH || here.startsWith(LOGIN_PATH + "?") || here.startsWith(LOGIN_PATH + "/")) {
    return LOGIN_PATH;
  }
  return LOGIN_PATH + "?redirect=" + encodeURIComponent(here);
}
