import type { Config } from "tailwindcss";

// 来源：MetaFusion/frontend/tailwind.config.ts（逐字复制，仅扩充 content 扫描范围以覆盖 src/shared）。
// 设计 token 的唯一来源是主仓库那份；改动请改主仓库再同步（共享层落地后替换为依赖引用）。
const config: Config = {
  content: ["./src/**/*.{js,ts,jsx,tsx,mdx}"],
  darkMode: "class",
  theme: {
    extend: {
      colors: {
        background: "rgb(var(--bg-rgb) / <alpha-value>)",
        surface: "rgb(var(--surface-rgb) / <alpha-value>)",
        surfaceHover: "rgb(var(--surface-hover-rgb) / <alpha-value>)",
        surfaceBorder: "var(--surface-border-color)",
        primary: {
          DEFAULT: "var(--primary-color)",
          hover: "var(--primary-hover-color)",
          light: "var(--primary-light-color)",
        },
        accent: {
          gold: "#f59e0b",
          cyan: "#06b6d4",
          emerald: "#10b981",
        },
        line: {
          DEFAULT: "var(--line-color)",
          subtle: "var(--line-subtle-color)",
          strong: "var(--line-strong-color)",
        },
        surfaceSubtle: "var(--surface-subtle-color)",
        text: {
          strong: "var(--text-strong-color)",
          body: "var(--text-body-color)",
          muted: "var(--text-muted-color)",
          faint: "var(--text-faint-color)",
        },
      },
      fontFamily: {
        sans: [
          "Inter",
          "ui-sans-serif",
          "-apple-system",
          "BlinkMacSystemFont",
          "Segoe UI",
          "Roboto",
          "Noto Sans SC",
          "sans-serif",
        ],
        mono: ["JetBrains Mono", "Fira Code", "ui-monospace", "SFMono-Regular", "monospace"],
        display: ["Instrument Serif", "Noto Serif SC", "Georgia", "serif"],
      },
      borderRadius: {
        none: "0px",
        xs: "6px",
        sm: "8px",
        DEFAULT: "12px",
        md: "12px",
        lg: "16px",
        xl: "20px",
        "2xl": "24px",
        "3xl": "28px",
        card: "16px",
        panel: "20px",
        control: "12px",
        chip: "8px",
        tech: "12px",
        pill: "9999px",
        full: "9999px",
      },
      maxWidth: {
        page: "80rem",
        narrow: "48rem",
      },
      transitionDuration: { fast: "120ms", base: "200ms" },
      transitionTimingFunction: { soft: "cubic-bezier(0.16, 1, 0.3, 1)" },
      boxShadow: {
        soft: "0 8px 24px -8px rgba(0,0,0,0.4)",
        elevated: "0 16px 48px -12px rgba(0,0,0,0.55)",
        glow: "0 2px 20px rgba(59,130,246,0.12)",
        "glow-amber": "0 2px 20px rgba(245,158,11,0.14)",
      },
      animation: {
        "fade-in": "fadeIn 0.35s cubic-bezier(0.16,1,0.3,1)",
        "slide-up": "slideUp 0.4s cubic-bezier(0.16,1,0.3,1)",
        "scale-in": "scaleIn 0.18s cubic-bezier(0.16,1,0.3,1)",
        shimmer: "shimmer 1.6s ease-in-out infinite",
      },
      keyframes: {
        fadeIn: { from: { opacity: "0" }, to: { opacity: "1" } },
        slideUp: {
          from: { opacity: "0", transform: "translateY(10px)" },
          to: { opacity: "1", transform: "translateY(0)" },
        },
        scaleIn: {
          from: { opacity: "0", transform: "scale(0.97)" },
          to: { opacity: "1", transform: "scale(1)" },
        },
        shimmer: {
          "0%": { backgroundPosition: "100% 0" },
          "100%": { backgroundPosition: "-100% 0" },
        },
      },
    },
  },
  plugins: [],
};
export default config;
