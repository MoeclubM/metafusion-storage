// 来源：MetaFusion/frontend/src/i18n/routing.ts（逐字复制）。
// 语言维度（四语码、NEXT_LOCALE cookie 名、Accept-Language 归一化）在主站与各服务自带 UI 之间必须逐字一致，
// 否则同一个浏览器在两个应用里会拿到不同语言。等共享层（packages/ 或协议层 SDK）落地后替换为依赖引用。
export const locales = ["zh-CN", "zh-TW", "ja-JP", "en-US"] as const;
export type Locale = (typeof locales)[number];
export const defaultLocale: Locale = "zh-CN";
export const localeCookieName = "NEXT_LOCALE";
export const validLocales = new Set<string>(locales);

export function normalizeLocale(input?: string | null): Locale {
  if (!input) return defaultLocale;
  const v = input.trim();
  if (validLocales.has(v)) return v as Locale;
  const low = v.toLowerCase().replace(/_/g, "-");
  if (low.startsWith("ja")) return "ja-JP";
  if (low.startsWith("zh-tw") || low.startsWith("zh-hk") || low.includes("hant")) return "zh-TW";
  if (low.startsWith("zh")) return "zh-CN";
  if (low.startsWith("en")) return "en-US";
  return defaultLocale;
}

export function parseAcceptLanguage(header?: string | null): Locale | null {
  if (!header) return null;
  for (const part of header.split(",")) {
    const tag = part.split(";")[0]?.trim();
    if (!tag) continue;
    if (validLocales.has(tag)) return tag as Locale;
    const low = tag.toLowerCase().replace(/_/g, "-");
    if (low.startsWith("ja")) return "ja-JP";
    if (low.startsWith("zh-tw") || low.startsWith("zh-hk") || low.includes("hant")) return "zh-TW";
    if (low.startsWith("zh")) return "zh-CN";
    if (low.startsWith("en")) return "en-US";
  }
  return null;
}
