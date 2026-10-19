"use client";

// Shared button: sm 32 / md 36 / lg 40px, md radius. One primary per screen.
// `loading` shows a spinner and disables the button while the action is in flight.
import type { ComponentType } from "react";
import { CircleNotch, type IconProps } from "@phosphor-icons/react";

const VARIANT = {
  primary: "bg-primary text-primary-foreground hover:bg-primary/90",
  secondary: "border border-border bg-card hover:bg-muted",
  ghost: "hover:bg-muted",
  danger: "bg-destructive text-primary-foreground hover:bg-destructive/90",
};
const SIZE = { sm: "h-8 px-3 text-label", md: "h-9 px-4 text-sm", lg: "h-10 px-5 text-sm" };

export type Variant = keyof typeof VARIANT;

export const btn = (variant: Variant = "secondary", size: keyof typeof SIZE = "md") =>
  `inline-flex shrink-0 items-center justify-center gap-2 rounded-md font-medium whitespace-nowrap transition-colors duration-150 active:scale-[.98] disabled:pointer-events-none disabled:opacity-55 ${VARIANT[variant]} ${SIZE[size]}`;

interface Props extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant;
  size?: keyof typeof SIZE;
  icon?: ComponentType<IconProps>;
  loading?: boolean;
}

export default function Button({ variant, size, icon: Icon, loading, children, disabled, className = "", ...rest }: Props) {
  return (
    <button type="button" {...rest} disabled={disabled || loading} aria-busy={loading || undefined} className={`${btn(variant, size)} ${className}`}>
      {loading ? <CircleNotch size={16} className="animate-spin" aria-hidden /> : Icon ? <Icon size={16} aria-hidden /> : null}
      {children}
    </button>
  );
}
