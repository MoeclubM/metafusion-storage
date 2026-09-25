"use client";
// 应用外壳：顶部（应用标识 + 当前身份 + 语言切换）、左侧导航、内容区。
// 与主站同域同路径前缀，因此语言与主题沿用同一套 cookie / localStorage 口径。
import React from "react";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { Badge, Icon } from "@/components/ui";
import { useSession } from "@/components/SessionProvider";
import { useI18n } from "@/shared/i18n/I18nProvider";
import { BASE_PATH } from "@/lib/app";
import { locales } from "@/shared/i18n/routing";

const NAV = [
  { href: "/", key: "nav.overview", icon: "gauge" },
  { href: "/assets", key: "nav.assets", icon: "search" },
  { href: "/bindings", key: "nav.bindings", icon: "unlink" },
];

export function AppShell({ subtitle, children }: { subtitle: string; children: React.ReactNode }) {
  const { t, locale, setLocale } = useI18n();
  const { state } = useSession();
  const pathname = usePathname();
  const router = useRouter();

  // usePathname 返回的是带 basePath 的完整路径，去掉前缀后才能与上面的 href 比。
  const rest = pathname.startsWith(BASE_PATH) ? pathname.slice(BASE_PATH.length) || "/" : pathname;
  const current = rest.replace(/\/+$/, "") || "/";

  return (
    <div className="min-h-screen bg-background">
      <header className="sticky top-0 z-30 border-b border-line bg-surface/70 backdrop-blur">
        <div className="mx-auto flex max-w-page flex-wrap items-center gap-3 px-4 py-3">
          <div className="flex min-w-0 items-center gap-2.5">
            <span className="grid h-8 w-8 place-items-center rounded-control border border-line bg-surfaceSubtle text-primary">
              <Icon name="file" className="w-4 h-4" />
            </span>
            <div className="min-w-0">
              <div className="truncate text-sm font-semibold text-text-strong">{t("common.appName")}</div>
              <div className="truncate text-[11px] text-text-muted">{subtitle}</div>
            </div>
          </div>

          <div className="ml-auto flex flex-wrap items-center gap-2">
            {state.status === "ready" ? (
              <>
                <span className="hidden text-[11px] text-text-muted sm:inline">
                  {t("session.signedInAs", { name: state.user.username })}
                </span>
                <span title={t("session.role", { role: state.user.role })}>
                  <Badge tone="neutral">{state.user.role}</Badge>
                </span>
                <span className="hidden text-[11px] text-text-faint md:inline">
                  {t("session.groups", {
                    groups: (state.user.groups ?? []).join(", ") || t("session.noGroups"),
                  })}
                </span>
              </>
            ) : null}
            <a href="/admin" className="rounded-control border border-line px-3 py-2 text-xs text-text-body hover:bg-surfaceHover">
              {t("nav.backToHub")}
            </a>
            <label className="flex items-center gap-2 text-xs text-text-muted">
              <span className="sr-only sm:not-sr-only">{t("common.language")}</span>
              <select value={locale} onChange={(e) => setLocale(e.target.value as typeof locale)} className="rounded-control border border-line bg-surface px-2 py-2 text-xs text-text-strong">
                {locales.map((loc) => <option key={loc} value={loc}>{loc}</option>)}
              </select>
            </label>
          </div>
        </div>
      </header>

      {/* 老令牌（或没配权限组的实例）不带 permissions 声明：这时界面与服务端都用历史角色兜底，
          不说清楚的话，用户会以为权限组没生效。 */}
      {state.status === "ready" && (state.user.permissions ?? []).length === 0 ? (
        <div className="border-b border-amber-500/30 bg-amber-500/5">
          <p className="mx-auto max-w-page px-4 py-2 text-[11px] leading-relaxed text-amber-400">
            {t("session.legacyFallback")}
          </p>
        </div>
      ) : null}

      <div className="mx-auto flex max-w-page flex-col gap-6 px-4 py-6 lg:flex-row">
        <nav className="shrink-0 lg:w-52" aria-label={t("nav.groupLabel")}>
          <div className="rounded-control border border-line bg-surfaceSubtle p-3 lg:hidden">
            <label htmlFor="storage-admin-section" className="mb-2 block text-xs font-medium text-text-muted">{t("nav.groupLabel")}</label>
            <select id="storage-admin-section" value={current} onChange={(e) => router.push(e.target.value)} className="w-full rounded-control border border-line bg-surface px-3 py-2.5 text-sm text-text-strong">
              {NAV.map((item) => <option key={item.href} value={item.href}>{t(item.key)}</option>)}
            </select>
          </div>
          <ul className="hidden rounded-control border border-line bg-surfaceSubtle p-2 lg:sticky lg:top-24 lg:flex lg:flex-col">
            {NAV.map((item) => {
              const active = current === item.href;
              return (
                <li key={item.href} className="shrink-0">
                  <Link
                    href={item.href}
                    aria-current={active ? "page" : undefined}
                    className={
                      "flex items-center gap-3 rounded-control px-3 py-2.5 text-sm transition-colors " +
                      (active
                        ? "bg-primary/15 font-semibold text-primary"
                        : "text-text-muted hover:bg-surfaceHover hover:text-text-body")
                    }
                  >
                    <Icon name={item.icon} className="w-4 h-4" />
                    {t(item.key)}
                  </Link>
                </li>
              );
            })}
          </ul>
        </nav>

        <main className="min-w-0 flex-1 space-y-4">{children}</main>
      </div>
    </div>
  );
}
