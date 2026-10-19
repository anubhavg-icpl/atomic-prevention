"use client";

import Link from "next/link";
import { ArrowRight, ArrowSquareOut, ChartBar, GitBranch, Lightning, ShieldCheck, Stack, Target } from "@phosphor-icons/react";
import AtomLogo from "@/components/atom-logo";
import { btn } from "@/components/button";
import { Mono } from "@/components/page-parts";
import StatusDot from "@/components/status-dot";

const REPO = "https://github.com/anubhavg-icpl/atomic-prevention";

const STATS = [
  { label: "ATT&CK techniques", value: "700+" },
  { label: "Adversary groups", value: "170+" },
  { label: "Data sources", value: "11" },
  { label: "Verdicts per test", value: "2" },
];

const FEATURES = [
  { icon: Stack, title: "Many sources, one framework", text: "LOLBAS, LOLDrivers, LOLRMM, Atomic Red Team and more, normalised into one test catalogue." },
  { icon: Target, title: "Mapped to ATT&CK", text: "Every test belongs to a technique and tactic. Build a playbook from the groups you actually face." },
  { icon: ShieldCheck, title: "Prevention, not detection", text: "Each test answers one question: was it blocked or allowed? You get a prevention score." },
  { icon: Lightning, title: "Playbooks you can run", text: "Export JSON, run it with the PowerShell or Python agent, and results flow back to the console." },
  { icon: ChartBar, title: "Coverage you can read", text: "A matrix of tactics and techniques shows exactly where controls hold and where they do not." },
  { icon: GitBranch, title: "Open and extensible", text: "Add a source by writing an ingester. Run it from the container image or build it yourself." },
];

const STEPS = [
  { title: "Ingest", text: "Pull LOL project data and the ATT&CK dataset." },
  { title: "Generate", text: "Pick an adversary group and get a mapped playbook." },
  { title: "Execute", text: "Run it on an authorised lab host with an agent." },
  { title: "Report", text: "Read blocked and allowed verdicts with a score." },
];

const SOURCES = [
  { name: "LOLBAS", text: "Living off the land binaries, scripts and libraries", url: "https://lolbas-project.github.io/" },
  { name: "LOLDrivers", text: "Vulnerable and malicious Windows drivers", url: "https://www.loldrivers.io/" },
  { name: "LOLRMM", text: "Remote monitoring and management tools", url: "https://lolrmm.io/" },
  { name: "Atomic Red Team", text: "Portable tests repurposed for prevention", url: "https://github.com/redcanaryco/atomic-red-team" },
];

export default function LandingPage() {
  return (
    <div className="min-h-dvh bg-background text-foreground">
      <header className="sticky top-0 z-topbar border-b border-border bg-background">
        <div className="mx-auto flex h-topbar max-w-6xl items-center justify-between px-6">
          <span className="flex items-center gap-3 font-semibold"><AtomLogo className="size-[30px] text-primary" />Atomic Prevention</span>
          <nav aria-label="Landing" className="flex items-center gap-2">
            <a href={REPO} target="_blank" rel="noopener noreferrer" className={btn("ghost", "sm")}>GitHub</a>
            <Link href="/" className={btn("primary", "sm")}>Open console</Link>
          </nav>
        </div>
      </header>

      <main>
        <section className="mx-auto max-w-6xl px-6 py-20">
          <h1 className="max-w-3xl text-3xl font-bold md:text-[2.75rem] md:leading-[1.15]">Test whether your controls actually block the attack.</h1>
          <p className="mt-4 max-w-2xl text-base text-muted-foreground">
            Atomic Prevention maps living-off-the-land techniques to MITRE ATT&amp;CK and runs them against your own hosts, so you see what prevention stops and what it lets through.
          </p>
          <div className="mt-8 flex flex-wrap gap-3">
            <Link href="/" className={btn("primary", "lg")}>Open console <ArrowRight size={16} aria-hidden /></Link>
            <a href={REPO} target="_blank" rel="noopener noreferrer" className={btn("secondary", "lg")}>View source <ArrowSquareOut size={16} aria-hidden /></a>
          </div>

          <dl className="mt-14 grid grid-cols-2 gap-4 md:grid-cols-4">
            {STATS.map((s) => (
              <div key={s.label} className="surface p-4">
                <dt className="text-label font-medium text-muted-foreground">{s.label}</dt>
                <dd className="mt-1 text-3xl font-bold tabular-nums">{s.value}</dd>
              </div>
            ))}
          </dl>
        </section>

        <section className="border-t border-border py-16" aria-labelledby="f-h">
          <div className="mx-auto max-w-6xl px-6">
            <h2 id="f-h" className="text-xl font-semibold">What it does</h2>
            <ul className="mt-6 grid gap-4 md:grid-cols-2 lg:grid-cols-3">
              {FEATURES.map(({ icon: Icon, title, text }) => (
                <li key={title} className="surface p-5">
                  <Icon size={20} className="text-primary-accent" aria-hidden />
                  <h3 className="mt-3 text-sm font-semibold">{title}</h3>
                  <p className="mt-1 text-sm text-muted-foreground">{text}</p>
                </li>
              ))}
            </ul>
          </div>
        </section>

        <section className="border-t border-border py-16" aria-labelledby="h-h">
          <div className="mx-auto max-w-6xl px-6">
            <h2 id="h-h" className="text-xl font-semibold">How it works</h2>
            <ol className="mt-6 grid gap-4 md:grid-cols-4">
              {STEPS.map((s, i) => (
                <li key={s.title} className="flex gap-3">
                  <span className="grid size-8 shrink-0 place-items-center rounded-full bg-primary text-sm font-semibold tabular-nums text-primary-foreground">{i + 1}</span>
                  <span><span className="block text-sm font-semibold">{s.title}</span><span className="block text-sm text-muted-foreground">{s.text}</span></span>
                </li>
              ))}
            </ol>
          </div>
        </section>

        <section className="border-t border-border py-16" aria-labelledby="s-h">
          <div className="mx-auto max-w-6xl px-6">
            <h2 id="s-h" className="text-xl font-semibold">Integrated sources</h2>
            <ul className="mt-6 grid gap-4 md:grid-cols-2 lg:grid-cols-4">
              {SOURCES.map((s) => (
                <li key={s.name}>
                  <a href={s.url} target="_blank" rel="noopener noreferrer" className="surface block h-full p-5 hover:bg-muted">
                    <span className="flex items-center justify-between text-sm font-semibold">{s.name}<ArrowSquareOut size={14} className="text-muted-foreground" aria-hidden /></span>
                    <span className="mt-1 block text-sm text-muted-foreground">{s.text}</span>
                  </a>
                </li>
              ))}
            </ul>
          </div>
        </section>

        <section className="border-t border-border py-16" aria-labelledby="q-h">
          <div className="mx-auto max-w-4xl px-6">
            <h2 id="q-h" className="text-xl font-semibold">Quick start</h2>
            <pre className="code-block mt-6 p-5 leading-6">{`# Run the console\ndocker compose up -d\n\n# On an authorised Windows lab host\nImport-Module ./agent/AtomicPrevention.psm1\nInvoke-AtomicPrevention -Playbook ./apt29-playbook.json`}</pre>
            <p className="mt-6 text-label font-medium text-muted-foreground">Sample agent output</p>
            <div className="surface mt-2 space-y-1.5 p-4 font-mono text-data">
              <p className="flex flex-wrap items-center gap-3"><StatusDot tone="ok" label="Blocked" /><Mono>T1059.001</Mono>PowerShell execution</p>
              <p className="flex flex-wrap items-center gap-3"><StatusDot tone="error" label="Allowed" /><Mono>T1218.011</Mono>Rundll32 proxy execution</p>
              <p className="flex flex-wrap items-center gap-3"><StatusDot tone="ok" label="Blocked" /><Mono>T1218.005</Mono>Mshta script execution</p>
            </div>
            <p className="mt-6 rounded-md border border-border bg-muted p-4 text-sm text-muted-foreground">
              Atomic Prevention runs real adversary-simulation commands. Use it only on systems you own or are explicitly authorised to test.
            </p>
          </div>
        </section>
      </main>

      <footer className="border-t border-border py-8 text-center text-sm text-muted-foreground">
        <a href={REPO} target="_blank" rel="noopener noreferrer" className="text-primary-accent hover:underline">Atomic Prevention</a> is open source.
      </footer>
    </div>
  );
}
