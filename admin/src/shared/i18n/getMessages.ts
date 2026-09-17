// 来源：MetaFusion/frontend/src/i18n/getMessages.ts（逐字复制，字典换成存储域这一份）。
// 字典按域拆：本应用只带存储管理台的键（解耦审计 §7.3「字典按域拆文件后合并」），
// 与主站整站字典不共享文件——四语键集合由 scripts/check-i18n.mjs 断言。
import { normalizeLocale, type Locale } from "./routing";
import zhCN from "@/messages/zh-CN.json";
import zhTW from "@/messages/zh-TW.json";
import jaJP from "@/messages/ja-JP.json";
import enUS from "@/messages/en-US.json";

const catalog: Record<string, Record<string, string>> = {
  "zh-CN": zhCN as Record<string, string>,
  "zh-TW": zhTW as Record<string, string>,
  "ja-JP": jaJP as Record<string, string>,
  "en-US": enUS as Record<string, string>,
};

export function getMessages(locale?: string | null): Record<string, string> {
  const loc = normalizeLocale(locale);
  return catalog[loc] || catalog["zh-CN"]!;
}

export function translate(
  messages: Record<string, string>,
  key: string,
  vars?: Record<string, string | number>
): string {
  let s = messages[key];
  if (s == null) return key;
  if (vars) {
    for (const [k, v] of Object.entries(vars)) {
      s = s.split(`{${k}}`).join(String(v));
    }
  }
  return s;
}

// translateOr 缺键时返回后备值而非裸 key：动态拼接键（如动态状态名）缺键时，
// 显示 fallback 比把键名端到用户面前更接近"如实但不说黑话"。
export function translateOr(
  messages: Record<string, string>,
  key: string,
  fallback: string,
  vars?: Record<string, string | number>
): string {
  if (messages[key] == null) return fallback;
  return translate(messages, key, vars);
}
