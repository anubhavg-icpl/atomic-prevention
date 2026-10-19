// Product mark: a shield (prevention) holding a nucleus and a single tilted orbit (atomic).
// Drawn in currentColor so it follows the theme token of whatever wraps it. Static in chrome.
export default function AtomLogo({ className = "size-6" }: { className?: string }) {
  return (
    <svg viewBox="0 0 40 40" className={className} fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinejoin="round" aria-hidden="true">
      <path d="M20 3 34 8v11c0 9-6 15-14 18C12 34 6 28 6 19V8z" />
      <ellipse cx="20" cy="20" rx="9.5" ry="3.8" transform="rotate(-35 20 20)" strokeWidth="1.8" />
      <circle cx="20" cy="20" r="3" fill="currentColor" stroke="none" />
    </svg>
  );
}
