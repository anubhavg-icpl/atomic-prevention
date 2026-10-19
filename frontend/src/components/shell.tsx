"use client";

// App shell: 262px sidebar (76px rail when collapsed), 58px topbar with the theme toggle.
// Navigation is real links with aria-current. The landing route renders without chrome.
import { useEffect, useState } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  BookOpenText, ChartBar, FileCode, Moon, SquaresFour, Sun, Target, UsersThree, DownloadSimple, CaretLeft, CaretRight, type IconProps,
} from "@phosphor-icons/react";
import type { ComponentType } from "react";
import AtomLogo from "./atom-logo";
import { API_BASE } from "@/lib/api";
import { btn } from "./button";

const NAV: { href: string; label: string; icon: ComponentType<IconProps> }[] = [
  { href: "/", label: "Dashboard", icon: SquaresFour },
  { href: "/techniques", label: "Techniques", icon: Target },
  { href: "/adversaries", label: "Adversaries", icon: UsersThree },
  { href: "/playbooks", label: "Playbooks", icon: BookOpenText },
  { href: "/results", label: "Results", icon: ChartBar },
  { href: "/docs", label: "API Docs", icon: FileCode },
];

const clean = (p: string) => (p.length > 1 ? p.replace(/\/$/, "") : p);

export default function Shell({ children }: { children: React.ReactNode }) {
  const pathname = clean(usePathname() || "/");
  const [collapsed, setCollapsed] = useState(false);
  const [dark, setDark] = useState(false);

  useEffect(() => {
    setDark(document.documentElement.classList.contains("dark"));
    setCollapsed(localStorage.getItem("rail") === "1");
  }, []);

  const toggleTheme = () => {
    const next = !dark;
    document.documentElement.classList.toggle("dark", next);
    localStorage.setItem("theme", next ? "dark" : "light");
    setDark(next);
  };
  const toggleRail = () => {
    localStorage.setItem("rail", collapsed ? "0" : "1");
    setCollapsed(!collapsed);
  };

  if (pathname === "/landing") return <>{children}</>;

  const active = (href: string) => (href === "/" ? pathname === "/" : pathname.startsWith(href));
  const current = NAV.find((n) => active(n.href));

  return (
    <div className="flex h-dvh overflow-hidden">
      <aside
        className={`relative z-sidebar hidden shrink-0 flex-col border-r border-border bg-sidebar transition-[width] duration-200 ease-out md:flex ${collapsed ? "w-rail" : "w-sidebar"}`}
      >
        <div className="flex h-topbar items-center gap-3 border-b border-border px-5">
          <Link href="/" aria-label="Atomic Prevention home" className="flex items-center gap-3">
            <AtomLogo className="size-[30px] shrink-0 text-primary" />
            {!collapsed && (
              <span className="leading-tight">
                <span className="block text-xs font-semibold text-muted-foreground">Prevention testing</span>
                <span className="block text-base font-semibold">Atomic Prevention</span>
              </span>
            )}
          </Link>
        </div>
        <button
          onClick={toggleRail}
          aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
          className="absolute left-[calc(100%-14px)] top-[72px] z-toggle grid size-7 place-items-center rounded-full border border-border bg-card shadow-sm hover:bg-muted"
        >
          {collapsed ? <CaretRight size={14} /> : <CaretLeft size={14} />}
        </button>
        <nav aria-label="Main" className="flex-1 space-y-0.5 overflow-y-auto p-3">
          {NAV.map(({ href, label, icon: Icon }) => (
            <Link
              key={href}
              href={href}
              title={collapsed ? label : undefined}
              aria-current={active(href) ? "page" : undefined}
              className={`flex items-center gap-3 rounded-md px-[11px] py-2 text-label transition-colors ${
                active(href) ? "bg-primary/15 font-semibold text-primary-accent" : "font-medium text-muted-foreground hover:bg-muted hover:text-foreground"
              } ${collapsed ? "justify-center" : ""}`}
            >
              <Icon size={16} aria-hidden />
              {!collapsed && label}
            </Link>
          ))}
        </nav>
        <div className="space-y-1 border-t border-border p-3">
          {[
            { href: "/api/agent/download", label: "Windows agent" },
            { href: "/api/agent/download-python", label: "Python agent" },
          ].map((a) => (
            <a key={a.href} href={`${API_BASE}${a.href}`} title={a.label} className="flex items-center gap-3 rounded-md px-[11px] py-2 text-label font-medium text-muted-foreground hover:bg-muted hover:text-foreground">
              <DownloadSimple size={16} aria-hidden />
              {!collapsed && a.label}
            </a>
          ))}
        </div>
      </aside>

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="z-topbar flex h-topbar shrink-0 items-center justify-between gap-2 border-b border-border bg-background px-4 md:justify-end">
          <Link href="/" aria-label="Atomic Prevention home" className="flex items-center gap-2 md:hidden">
            <AtomLogo className="size-6 text-primary" />
            <span className="font-semibold">Atomic Prevention</span>
          </Link>
          <button onClick={toggleTheme} className={btn("ghost", "sm")} aria-label={dark ? "Switch to light theme" : "Switch to dark theme"}>
            {dark ? <Sun size={16} /> : <Moon size={16} />}
            <span className="hidden sm:inline">{dark ? "Light" : "Dark"}</span>
          </button>
        </header>
        <nav aria-label="Mobile" className="flex gap-1 overflow-x-auto border-b border-border px-3 py-2 md:hidden">
          {NAV.map(({ href, label }) => (
            <Link key={href} href={href} aria-current={active(href) ? "page" : undefined} className={`rounded-md px-3 py-1.5 text-label whitespace-nowrap ${active(href) ? "bg-primary/15 font-semibold text-primary-accent" : "text-muted-foreground"}`}>
              {label}
            </Link>
          ))}
        </nav>
        <main className="flex-1 overflow-y-auto px-[30px] py-[26px]" data-page={current?.label}>
          <div className="mx-auto max-w-[1400px] space-y-6">{children}</div>
        </main>
      </div>
    </div>
  );
}
