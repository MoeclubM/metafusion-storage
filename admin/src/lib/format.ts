// 纯展示格式化。日期一律走 Intl + 当前 locale：管理台与主站都只展示本地时间，
// 不做时区换算（服务端给的就是带时区的 RFC3339，浏览器本地化即可）。

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function isUuid(v: string): boolean {
  return UUID_RE.test(v.trim());
}

/** 从"纯 uuid 或含 uuid 的地址"里取出 uuid：运维手里多半是复制来的 URL，不该逼人手工裁剪。 */
export function extractUuid(input: string): string {
  const m = input.trim().match(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i);
  return m ? m[0] : "";
}

export function formatInt(value: number, locale: string): string {
  return new Intl.NumberFormat(locale).format(value);
}

const UNITS = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];

/** 二进制单位（1 KiB = 1024 B）：服务端 size_bytes 是字节数，展示用 IEC 前缀更贴近运维口径。 */
export function formatBytes(bytes: number, locale: string): string {
  if (!Number.isFinite(bytes) || bytes < 0) return "—";
  if (bytes < 1024) return formatInt(bytes, locale) + " B";
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < UNITS.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return new Intl.NumberFormat(locale, { maximumFractionDigits: 2 }).format(value) + " " + UNITS[unit];
}

export function formatDateTime(value: string | null | undefined, locale: string): string {
  if (!value) return "—";
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return value;
  return new Intl.DateTimeFormat(locale, { dateStyle: "medium", timeStyle: "medium" }).format(d);
}

/** 短 id（uuid 前 8 位）+ 完整值并列展示：列表里要能扫，复制时要能拿到全的。 */
export function shortId(id: string): string {
  return id.length > 12 ? id.slice(0, 8) : id;
}
