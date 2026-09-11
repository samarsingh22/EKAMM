import { NavLink } from "react-router-dom";
import clsx from "clsx";
import {
  LayoutDashboard,
  ScrollText,
  Radio,
  Blocks,
  ShieldCheck,
  ActivitySquare,
  Inbox,
} from "lucide-react";
import type { LucideIcon } from "lucide-react";

interface NavItem {
  to: string;
  label: string;
  icon: LucideIcon;
  end?: boolean;
}

const NAV_ITEMS: NavItem[] = [
  { to: "/console", label: "Overview", icon: LayoutDashboard, end: true },
  { to: "/events", label: "Events", icon: ScrollText },
  { to: "/sources", label: "Sources", icon: Radio },
  { to: "/templates", label: "Templates", icon: Blocks },
  { to: "/integrity", label: "Integrity", icon: ShieldCheck },
  { to: "/anomalies", label: "Anomalies", icon: ActivitySquare },
  { to: "/dlq", label: "Dead Letters", icon: Inbox },
];

export default function Sidebar() {
  return (
    <aside className="flex w-56 shrink-0 flex-col border-r border-border bg-bg-panel">
      <div className="flex h-14 items-center gap-2 border-b border-border px-4">
        {/* EKAM mark, as on the landing page: the face follows the text colour,
            the blue and slate strata are brand-fixed. */}
        <svg className="h-6 w-auto shrink-0" viewBox="0 0 120 102" aria-hidden="true">
          <path className="fill-text" d="M60 2 L83.7 42 L49.3 42 L15 100 L2 100 Z" />
          <path fill="#0b63f6" d="M47 46 L86 46 L96.7 64 L36.3 64 Z" />
          <path fill="#74899e" d="M32.8 70 L100.2 70 L118 100 L15 100 Z" />
        </svg>
        {/* one inline run so EKAM and the Devanagari share a baseline */}
        <span className="whitespace-nowrap text-lg font-extrabold leading-none tracking-tight text-text">
          EKAM <span className="text-[0.84em] font-bold tracking-normal">(एकम्)</span>
        </span>
      </div>

      <nav className="flex-1 space-y-0.5 overflow-y-auto p-2">
        {NAV_ITEMS.map(({ to, label, icon: Icon, end }) => (
          <NavLink
            key={to}
            to={to}
            end={end}
            className={({ isActive }) =>
              clsx(
                "flex items-center gap-2.5 rounded-md px-3 py-2 text-sm transition-colors",
                isActive
                  ? "bg-accent-bg text-accent"
                  : "text-text-muted hover:bg-bg-elevated hover:text-text",
              )
            }
          >
            <Icon className="h-4 w-4 shrink-0" strokeWidth={2} />
            <span>{label}</span>
          </NavLink>
        ))}
      </nav>

      {/* <div className="border-t border-border p-3 text-[11px] text-text-faint">
        Smart India Hackathon 2026 · PS 26156
      </div> */}
    </aside>
  );
}
