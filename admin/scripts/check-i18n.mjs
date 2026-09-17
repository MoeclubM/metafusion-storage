#!/usr/bin/env node
// i18n 一致性断言（CI 与本地都跑）：四语字典的键集合必须完全一致，
// 并且源码里用到的每个字面量键都要在四语里存在——缺一边就是"某语言显示键名"。
//
// 为什么要有这个脚本：字典按域拆到各服务自带 UI 之后，没有任何工具能靠类型系统发现
// "只补了 zh-CN" 的漏译；这里把三件事钉死：键集合、占位符集合、源码引用。
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const LOCALES = ["zh-CN", "zh-TW", "ja-JP", "en-US"];

/** 收集源码里 t("k") / tr("k", ...) 的字面量键（只认带点的键，避免误伤普通函数调用）。 */
function collectUsedKeys(dir, acc) {
  for (const name of readdirSync(dir)) {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) {
      collectUsedKeys(path, acc);
      continue;
    }
    if (!/\.(ts|tsx)$/.test(name)) continue;
    const src = readFileSync(path, "utf8");
    // 键必须是"逐段都是词字符"的点分路径：`tr("a.b." + x, …)` 这类动态前缀不会被当成字面量键。
    // 三种写法都要收：t("k") / tr("k", …)、Message 对象的 { key: "k" }、字典直取 messages["k"]
    // （后两种不经过 t()，漏收就会把在用的键报成死键）。
    for (const re of [/\bt(?:r)?\(\s*"([a-zA-Z][\w]*(?:\.[\w]+)+)"/g, /\bkey:\s*"([a-zA-Z][\w]*(?:\.[\w]+)+)"/g, /\bmessages\["([a-zA-Z][\w]*(?:\.[\w]+)+)"\]/g]) {
      for (const m of src.matchAll(re)) acc.add(m[1]);
    }
  }
  return acc;
}

function placeholders(value) {
  return [...value.matchAll(/\{(\w+)\}/g)].map((m) => m[1]).sort().join(",");
}

const problems = [];
const dicts = {};
for (const locale of LOCALES) {
  const raw = readFileSync(join(root, "src/messages", locale + ".json"), "utf8");
  // JSON.parse 会静默吃掉重复键，重复键必须先按文本查一遍。
  const seen = new Set();
  for (const m of raw.matchAll(/^\s*"([^"]+)":/gm)) {
    if (seen.has(m[1])) problems.push(locale + ": duplicate key " + m[1]);
    seen.add(m[1]);
  }
  dicts[locale] = JSON.parse(raw);
}

const base = new Set(Object.keys(dicts["zh-CN"]));
for (const locale of LOCALES) {
  const keys = new Set(Object.keys(dicts[locale]));
  const missing = [...base].filter((k) => !keys.has(k));
  const extra = [...keys].filter((k) => !base.has(k));
  if (missing.length) problems.push(locale + ": missing " + missing.length + " key(s): " + missing.slice(0, 10).join(", "));
  if (extra.length) problems.push(locale + ": extra " + extra.length + " key(s): " + extra.slice(0, 10).join(", "));
  for (const [key, value] of Object.entries(dicts[locale])) {
    if (typeof value !== "string" || value.trim() === "") problems.push(locale + ": empty value for " + key);
  }
}

// 占位符必须逐语一致：少一个 {code} 就等于那句话把服务端给的错误码吞了。
for (const key of base) {
  const expected = placeholders(dicts["zh-CN"][key]);
  for (const locale of LOCALES) {
    const got = placeholders(dicts[locale][key] ?? "");
    if (got !== expected) problems.push(locale + ": placeholder mismatch for " + key + " (" + expected + " vs " + got + ")");
  }
}

const used = collectUsedKeys(join(root, "src"), new Set());
for (const key of used) {
  if (!base.has(key)) problems.push("used in source but absent from zh-CN: " + key);
}
// 拼接出来的键（\`tr("assets.status." + status)\`、tab 元组里的 "bindings.mode*"）扫不到字面量，
// 单列成"动态族"：族内的键允许无人引用，别的键无人引用就是死键，会被报出来。
const DYNAMIC_KEY_FAMILIES = ["assets.status.", "bindings.mode"];

// 反向只报告、不失败：动态键与预留键都可能暂时无人引用。
const unused = [...base].filter((k) => !used.has(k) && !DYNAMIC_KEY_FAMILIES.some((p) => k.startsWith(p)));

if (problems.length) {
  console.error("i18n check failed:");
  for (const p of problems) console.error("  - " + p);
  process.exit(1);
}
console.log("i18n ok: " + base.size + " keys x " + LOCALES.length + " locales, " + used.size + " referenced in source");
if (unused.length) console.log("note: " + unused.length + " key(s) not referenced by a literal: " + unused.join(", "));
