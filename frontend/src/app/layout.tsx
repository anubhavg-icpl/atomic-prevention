import type { Metadata } from "next";
import { GeistSans } from "geist/font/sans";
import { GeistMono } from "geist/font/mono";
import Shell from "@/components/shell";
import "./globals.css";

export const metadata: Metadata = {
  title: { default: "Atomic Prevention", template: "%s · Atomic Prevention" },
  description: "Prevention testing for living-off-the-land techniques, mapped to MITRE ATT&CK.",
  icons: { icon: "/favicon.svg" },
};

// Runs before first paint so the persisted theme never flashes the wrong one.
const THEME_BOOT = `try{var t=localStorage.getItem("theme");if(t==="dark"||(!t&&matchMedia("(prefers-color-scheme: dark)").matches))document.documentElement.classList.add("dark")}catch(e){}`;

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" suppressHydrationWarning className={`${GeistSans.variable} ${GeistMono.variable}`}>
      <head>
        <script dangerouslySetInnerHTML={{ __html: THEME_BOOT }} />
      </head>
      <body>
        <Shell>{children}</Shell>
      </body>
    </html>
  );
}
