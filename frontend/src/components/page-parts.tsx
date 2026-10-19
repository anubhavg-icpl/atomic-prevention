"use client";

// Page chrome shared by every route: header, badge, and the loading/empty/error states.
import type { ComponentType, ReactNode } from "react";
import { WarningCircle, type IconProps } from "@phosphor-icons/react";
import Button from "./button";

export function PageHeader({ title, description, actions }: { title: string; description?: string; actions?: ReactNode }) {
  return (
    <header className="flex flex-wrap items-start justify-between gap-3">
      <div className="min-w-0">
        <h1 className="text-base font-medium">{title}</h1>
        {description && <p className="mt-0.5 text-sm text-muted-foreground">{description}</p>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </header>
  );
}

export const Badge = ({ children }: { children: ReactNode }) => (
  <span className="inline-flex items-center rounded-sm border border-border bg-muted px-1.5 py-0.5 text-xs font-medium text-muted-foreground">
    {children}
  </span>
);

export const Mono = ({ children }: { children: ReactNode }) => (
  <span className="font-mono text-data text-primary-accent">{children}</span>
);

export function Skeleton({ rows = 4 }: { rows?: number }) {
  return (
    <div className="space-y-2" role="status" aria-label="Loading">
      {Array.from({ length: rows }, (_, i) => (
        <div key={i} className="skeleton h-16" />
      ))}
    </div>
  );
}

export function Empty({ icon: Icon, title, hint, action }: { icon: ComponentType<IconProps>; title: string; hint?: string; action?: ReactNode }) {
  return (
    <div className="surface flex flex-col items-center px-6 py-12 text-center">
      <Icon size={28} className="text-muted-foreground" aria-hidden />
      <h2 className="mt-3 text-xl font-semibold">{title}</h2>
      {hint && <p className="mt-1 max-w-md text-sm text-muted-foreground">{hint}</p>}
      {action && <div className="mt-4">{action}</div>}
    </div>
  );
}

export function ErrorState({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <div className="surface flex items-start gap-3 p-4" role="alert">
      <WarningCircle size={20} className="mt-0.5 text-destructive" aria-hidden />
      <div className="min-w-0 flex-1">
        <p className="text-sm font-medium">Could not load this view</p>
        <p className="mt-0.5 break-words font-mono text-data text-muted-foreground">{message}</p>
      </div>
      {onRetry && <Button size="sm" onClick={onRetry}>Retry</Button>}
    </div>
  );
}
