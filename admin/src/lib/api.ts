import { extractUuid } from "./format";

// 同域数据面：管理台与存储服务在同一个域名下由网关按路径聚合，
// 因此数据请求直接打同源 /api/storage（由网关分流回存储服务），cookie 自然带上。
// 不在 next.config.mjs 里配 rewrites：basePath 会连带前缀改写 rewrite 的 source，
// 一条 "/api/:path*" 会把本应用自己的 app/api/health 一起吞掉。
export const API_BASE = process.env.NEXT_PUBLIC_STORAGE_API_BASE || "/api/storage";

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;

  constructor(status: number, code: string) {
    super(code || "request_failed");
    this.name = "ApiError";
    this.status = status;
    this.code = code || "request_failed";
  }
}

/** 界面文案用 Message 描述而不是字符串：字典在组件层解析，错误层不引入 i18n 依赖。 */
export type Message = { key: string; vars?: Record<string, string | number> };

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let res: Response;
  try {
    res = await fetch(API_BASE.replace(/\/$/, "") + path, {
      // no-store：可见性按请求判定，任何一层缓存复用都会把一次成功鉴权的响应发给无权者。
      cache: "no-store",
      credentials: "include",
      headers: { Accept: "application/json", ...(init?.headers ?? {}) },
      ...init,
    });
  } catch (err) {
    throw new Error("NETWORK:" + (err instanceof Error ? err.message : String(err)));
  }
  const text = await res.text();
  let body: unknown = null;
  if (text) {
    try {
      body = JSON.parse(text);
    } catch {
      body = null;
    }
  }
  if (!res.ok) {
    const code =
      body && typeof body === "object" && typeof (body as { error?: unknown }).error === "string"
        ? (body as { error: string }).error
        : "";
    throw new ApiError(res.status, code);
  }
  return body as T;
}

export function apiGet<T>(path: string): Promise<T> {
  return request<T>(path, { method: "GET" });
}

export function apiDelete<T>(path: string): Promise<T> {
  return request<T>(path, { method: "DELETE" });
}

/**
 * 把接口错误翻成界面文案。服务端的错误码是稳定的（见 internal/handler 的 fail 调用），
 * 所以按码分支即可；opts.notFound 用来在"404 有特定含义"的位置换一句更贴切的话。
 */
export function describeApiError(err: unknown, opts?: { notFound?: Message }): Message {
  if (err instanceof ApiError) {
    if (err.code === "authentication_required" || err.status === 401) return { key: "errors.authentication_required" };
    // 这一条必须在 404 分支之前：object_missing 是 404，但它的语义是"元数据在、字节没了"，
    // 与"没有这个资产"不同，混成一句会让运营以为换个 id 就能找到内容。
    if (err.code === "object_missing") return { key: "errors.object_missing" };
    if (err.status === 404 || err.code === "not_found") return opts?.notFound ?? { key: "errors.not_found" };
    if (err.code === "forbidden" || err.status === 403) return { key: "errors.forbidden" };
    if (err.code === "module_error") return { key: "errors.module_error" };
    if (err.code === "storage_unavailable") return { key: "errors.storage_unavailable" };
    if (err.code === "invalid_payload") return { key: "errors.invalid_payload" };
    if (err.status >= 500) return { key: "errors.module_error" };
    return { key: "errors.generic", vars: { status: err.status, code: err.code } };
  }
  const raw = err instanceof Error ? err.message : String(err);
  if (raw.startsWith("NETWORK:")) return { key: "errors.network", vars: { message: raw.slice("NETWORK:".length) } };
  return { key: "errors.network", vars: { message: raw } };
}

/** 资产/绑定 id 都是 uuid：本地先挡一道，省一次注定 404 的请求；服务端口径一致（非法字面量按不存在处理）。 */
export function normalizeIdInput(input: string): string {
  return extractUuid(input);
}
