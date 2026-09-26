import { apiDelete, apiGet, apiPost } from "./api";

// 类型照着服务端 DTO 写（internal/store/store.go 的 Asset / Binding），字段名逐字一致：
// 少一个字段不会报错，只会让界面空着，所以这里按"服务端有什么就写什么"对齐。

export type Asset = {
  id: string;
  sha256: string;
  size_bytes: number;
  declared_size: number;
  mime_type: string;
  file_name: string;
  object_key: string;
  status: string;
  multipart_upload_id?: string;
  hash_verified: boolean;
  uploader_id: string;
  fail_reason?: string;
  created_at: string;
  completed_at?: string | null;
  blocked: boolean;
  blocked_reason?: string;
  blocked_at?: string | null;
};

export type Binding = {
  id: string;
  asset_id: string;
  target_entity_id: string;
  target_kind: string;
  binding_role: string;
  created_by: string;
  created_at: string;
};

export type AssetResponse = { asset: Asset; bindings: Binding[] | null };

/** 列表视图：绑定 + 它指向的文件元数据（服务端 FileBinding）。 */
export type FileBinding = Binding & { asset: Asset };

export type EntityFilesResponse = {
  target_entity_id: string;
  target_kind: string;
  files: FileBinding[] | null;
};

export type StatsResponse = { assets: number; bytes: number; pending: number; blocked: number };

/** GET /api/storage/stats —— 完成态用量、待完成与禁发数。 */
export function fetchStats(): Promise<StatsResponse> {
  return apiGet<StatsResponse>("/stats");
}

export type BlockedAssetsResponse = { assets: Asset[]; limit: number; offset: number };

export function fetchBlockedAssets(limit = 100, offset = 0): Promise<BlockedAssetsResponse> {
  return apiGet<BlockedAssetsResponse>(`/moderation/blocked?limit=${limit}&offset=${offset}`);
}

export function setAssetBlocked(id: string, blocked: boolean, reason?: string): Promise<{ asset: Asset }> {
  return apiPost<{ asset: Asset }>(`/assets/${encodeURIComponent(id)}/${blocked ? "block" : "unblock"}`, blocked ? { reason } : undefined);
}

/** GET /api/storage/assets/:id —— 文件元数据 + 绑定列表（不可读与不存在同为 404）。 */
export function fetchAsset(id: string): Promise<AssetResponse> {
  return apiGet<AssetResponse>("/assets/" + encodeURIComponent(id));
}

/** GET /api/storage/entities/:id/files —— 实体可见性由目录服务判定。 */
export function fetchEntityFiles(entityId: string): Promise<EntityFilesResponse> {
  return apiGet<EntityFilesResponse>("/entities/" + encodeURIComponent(entityId) + "/files");
}

/** DELETE /api/storage/bindings/:id —— 不幂等：第二次删同一个 id 是 404。 */
export function deleteBinding(bindingId: string): Promise<{ ok: boolean }> {
  return apiDelete<{ ok: boolean }>("/bindings/" + encodeURIComponent(bindingId));
}

/** 内联预览地址：服务端每次重新鉴权后原样转发对象内容（不转码、可被 <img> 直接加载）。 */
export function assetContentUrl(assetId: string): string {
  return "/api/storage/assets/" + encodeURIComponent(assetId) + "/content";
}

/** 取件地址：对象存储模式只回预签名地址，本地模式直接流式下发。 */
export function assetDownloadUrl(assetId: string): string {
  return "/api/storage/download/" + encodeURIComponent(assetId);
}

/** 预览能力判定只认 MIME（服务端 inline 分发时的类型优先取登记的 mime_type）。 */
export type PreviewKind = "image" | "video" | "audio" | "pdf" | "none";

export function previewKind(mime: string): PreviewKind {
  const m = (mime || "").toLowerCase();
  if (m.startsWith("image/")) return "image";
  if (m.startsWith("video/")) return "video";
  if (m.startsWith("audio/")) return "audio";
  if (m === "application/pdf") return "pdf";
  return "none";
}
