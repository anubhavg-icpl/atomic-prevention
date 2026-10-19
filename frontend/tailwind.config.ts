import type { Config } from "tailwindcss";

// Every colour is a token from globals.css (Invinsense Module UI Guide v2.0, §05).
// Never add a raw hex here: if a colour is missing, the token is missing.
const oklch = (v: string) => `oklch(var(--${v}) / <alpha-value>)`;
const hsl = (v: string) => `hsl(var(--${v}) / <alpha-value>)`;

const config: Config = {
  darkMode: "class",
  content: ["./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        background: oklch("background"),
        foreground: oklch("foreground"),
        card: oklch("card"),
        popover: oklch("popover"),
        primary: { DEFAULT: oklch("primary"), foreground: oklch("primary-foreground"), accent: oklch("primary-accent") },
        muted: { DEFAULT: oklch("muted"), foreground: oklch("muted-foreground") },
        destructive: oklch("destructive"),
        // Border and input carry their own alpha in dark mode, so no <alpha-value>.
        border: "oklch(var(--border))",
        input: "oklch(var(--input))",
        ring: oklch("ring"),
        sidebar: oklch("sidebar"),
        status: {
          ok: hsl("status-ok"),
          degraded: hsl("status-degraded"),
          error: hsl("status-error"),
          idle: hsl("status-idle"),
          "ok-text": hsl("status-ok-text"),
          "degraded-text": hsl("status-degraded-text"),
          "error-text": hsl("status-error-text"),
          "idle-text": hsl("status-idle-text"),
        },
      },
      fontFamily: {
        sans: ["var(--font-geist-sans)", "Geist Fallback", "ui-sans-serif", "system-ui", "sans-serif"],
        mono: ["var(--font-geist-mono)", "ui-monospace", "Menlo", "monospace"],
      },
      fontSize: {
        // §06 type scale. 12px is the floor (Law 9): nothing smaller exists here.
        xs: ["0.75rem", "1rem"],
        label: ["0.8125rem", "1.125rem"],
        data: ["0.8125rem", "1.25rem"],
        sm: ["0.875rem", "1.25rem"],
        base: ["1rem", "1.5rem"],
        lg: ["1.125rem", "1.625rem"],
        xl: ["1.25rem", "1.75rem"],
        "3xl": ["1.875rem", "2.25rem"],
      },
      borderRadius: { sm: "6px", md: "8px", lg: "10px", xl: "14px" },
      spacing: { topbar: "58px", sidebar: "262px", rail: "76px" },
      zIndex: { raised: "10", sticky: "20", sidebar: "40", toggle: "45", topbar: "50", dropdown: "100", overlay: "200", modal: "300" },
    },
  },
  plugins: [],
};

export default config;
