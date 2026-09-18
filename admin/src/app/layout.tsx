import type { Metadata } from "next";
import { cookies } from "next/headers";
import { AppShell } from "@/components/AppShell";
import { SessionProvider } from "@/components/SessionProvider";
import { getMessages } from "@/shared/i18n/getMessages";
import { I18nProvider } from "@/shared/i18n/I18nProvider";
import { localeCookieName, normalizeLocale } from "@/shared/i18n/routing";
import "@/shared/theme/globals.css";

// 语言在服务端就定下来（读 NEXT_LOCALE cookie），避免首屏先按默认语言渲染再跳到用户语言。
//
// robots 必须写在这里，不能只靠 public/robots.txt：本应用 basePath 是 /admin/storage，
// 那份 robots.txt 会被服务在 /admin/storage/robots.txt，而爬虫只读源站根的 /robots.txt
// （由主前端作答），等于没有任何收录防护。账号与社区两个管理台同样是靠这条 meta 收敛的。
// cookies() 是异步请求 API（Next 15 起返回 Promise，Next 16 不再接受同步取值）。
export async function generateMetadata(): Promise<Metadata> {
  const locale = normalizeLocale((await cookies()).get(localeCookieName)?.value);
  const messages = getMessages(locale);
  return {
    title: messages["meta.title"],
    description: messages["meta.description"],
    robots: { index: false, follow: false },
  };
}

// 主题与主站共用 localStorage 口径（metafusion_theme_mode / _accent / _tone）：登录态、语言、主题
// 三样在四个应用之间必须是同一份选择，因此在首次绘制前把 <html> 的属性补齐（复制自主仓库
// MetaFusion/frontend/src/lib/themeContext.tsx 的 applyTheme；共享层落地后替换为依赖引用）。
const themeScript = [
  "(function () {",
  "  try {",
  "    var mode = localStorage.getItem(\"metafusion_theme_mode\") || \"dark\";",
  "    var accent = localStorage.getItem(\"metafusion_theme_accent\");",
  "    var tone = localStorage.getItem(\"metafusion_theme_tone\");",
  "    var effective = mode === \"system\"",
  "      ? (window.matchMedia(\"(prefers-color-scheme: dark)\").matches ? \"dark\" : \"light\")",
  "      : mode;",
  "    var root = document.documentElement;",
  "    root.setAttribute(\"data-theme-mode\", effective);",
  "    if (accent) root.setAttribute(\"data-theme-accent\", accent);",
  "    if (tone) root.setAttribute(\"data-theme-tone\", tone);",
  "    root.classList.toggle(\"dark\", effective === \"dark\");",
  "    root.classList.toggle(\"light\", effective === \"light\");",
  "    root.style.colorScheme = effective;",
  "  } catch (e) {}",
  "})();",
].join("\n");

export default async function RootLayout({ children }: { children: React.ReactNode }) {
  const locale = normalizeLocale((await cookies()).get(localeCookieName)?.value);
  const messages = getMessages(locale);
  return (
    <html lang={locale} className="dark" data-theme-mode="dark" suppressHydrationWarning>
      <head>
        <script dangerouslySetInnerHTML={{ __html: themeScript }} />
      </head>
      <body className="antialiased">
        <I18nProvider initialLocale={locale}>
          <SessionProvider>
            <AppShell subtitle={messages["common.appSubtitle"]}>{children}</AppShell>
          </SessionProvider>
        </I18nProvider>
      </body>
    </html>
  );
}
