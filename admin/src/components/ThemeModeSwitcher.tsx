"use client";

import { useEffect, useRef, useState } from "react";
import { useI18n } from "@/shared/i18n/I18nProvider";

type Mode = "dark" | "light" | "system";
const KEY = "metafusion_theme_mode";

function apply(mode: Mode) {
  const effective = mode === "system"
    ? (window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light")
    : mode;
  const root = document.documentElement;
  root.setAttribute("data-theme-mode", effective);
  root.classList.toggle("dark", effective === "dark");
  root.classList.toggle("light", effective === "light");
  root.style.colorScheme = effective;
}

export function ThemeModeSwitcher() {
  const { t } = useI18n();
  const [mode, setMode] = useState<Mode>("dark");
  const [open, setOpen] = useState(false);
  const container = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const sync = () => {
      const value = localStorage.getItem(KEY);
      const next: Mode = value === "light" || value === "system" ? value : "dark";
      setMode(next);
      apply(next);
    };
    sync();
    const media = window.matchMedia("(prefers-color-scheme: dark)");
    media.addEventListener("change", sync);
    window.addEventListener("storage", sync);
    return () => { media.removeEventListener("change", sync); window.removeEventListener("storage", sync); };
  }, []);
  useEffect(() => {
    if (!open) return;
    const onPointer = (event: MouseEvent) => {
      if (!container.current?.contains(event.target as Node)) setOpen(false);
    };
    const onKey = (event: KeyboardEvent) => { if (event.key === "Escape") setOpen(false); };
    document.addEventListener("mousedown", onPointer);
    document.addEventListener("keydown", onKey);
    return () => { document.removeEventListener("mousedown", onPointer); document.removeEventListener("keydown", onKey); };
  }, [open]);
  const choose = (next: Mode) => {
    localStorage.setItem(KEY, next);
    setMode(next);
    apply(next);
    setOpen(false);
  };
  return <div className="relative" ref={container}>
    <button type="button" aria-label={t("theme.modeLabel")} title={t("theme.modeLabel")} aria-expanded={open} aria-haspopup="menu" onClick={() => setOpen(!open)} className="grid h-9 w-9 place-items-center rounded-full border border-line bg-surfaceSubtle text-text-body hover:bg-surfaceHover">
      <span className="text-base leading-none text-primary" aria-hidden="true">{mode === "light" ? "☀" : "☾"}</span>
    </button>
    {open ? <div role="menu" aria-label={t("theme.modeLabel")} className="absolute right-0 z-50 mt-2 w-44 rounded-card border border-line bg-surface p-1.5 shadow-elevated">
      {(["dark", "light", "system"] as const).map((item) => <button key={item} type="button" role="menuitemradio" aria-checked={mode === item} onClick={() => choose(item)} className={"flex w-full items-center justify-between rounded-control px-3 py-2 text-left text-xs hover:bg-surfaceHover " + (mode === item ? "font-semibold text-primary" : "text-text-body")}>
        {t("theme." + item)}{mode === item ? "✓" : null}
      </button>)}
    </div> : null}
  </div>;
}
