"use client";
// 应用外壳：顶部（应用标识 + 当前身份 + 语言切换）、左侧导航、内容区。
// 与主站同域同路径前缀，因此语言与主题沿用同一套 cookie / localStorage 口径。
import React from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { Badge, Icon } from "@/components/ui";
import { useSession } from "@/components/SessionProvider";
import { useI18n } from "@/shared/i18n/I18nProvider";
import { BASE_PATH, SERVICE_NAME } from "@/lib/app";
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

  // usePathname 返回的是带 basePath 的完整路径，去掉前缀后才能与上面的 href 比。
  const rest = pathname.startsWith(BASE_PATH) ? pathname.slice(BASE_PATH.length) || "/" : pathname;
  const current = rest === "" ? "/" : rest;

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
            <Badge tone="neutral">{SERVICE_NAME}</Badge>
            <div className="flex items-center gap-1" role="group" aria-label={t("common.language")}>
              {locales.map((loc) => (
                <button
                  key={loc}
                  type="button"
                  onClick={() => setLocale(loc)}
                  aria-pressed={locale === loc}
                  className={
                    "rounded-chip border px-2 py-0.5 font-mono text-[11px] transition-colors " +
                    (locale === loc ? "border-primary text-primary" : "border-line text-text-muted hover:bg-surfaceHover")
                  }
                >
                  {loc}
                </button>
              ))}
            </div>
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
          <ul className="flex gap-1 overflow-x-auto lg:flex-col lg:overflow-visible">
            {NAV.map((item) => {
              const active = current === item.href;
              return (
                <li key={item.href} className="shrink-0">
                  <Link
                    href={item.href}
                    aria-current={active ? "page" : undefined}
                    className={
                      "flex items-center gap-2 rounded-control border px-3 py-2 text-xs transition-colors " +
                      (active
                        ? "border-primary/40 bg-primary/10 text-primary"
                        : "border-transparent text-text-muted hover:bg-surfaceHover hover:text-text-body")
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
