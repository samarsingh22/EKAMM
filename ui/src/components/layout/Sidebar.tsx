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
  { to: "/", label: "Overview", icon: LayoutDashboard, end: true },
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
        <ShieldCheck className="h-5 w-5 text-accent" strokeWidth={2} />
        <div className="leading-none">
          <div className="text-sm font-semibold tracking-wide text-text">ULPF</div>
          <div className="text-[10px] uppercase tracking-wider text-text-faint">
            log pre-processing
          </div>
        </div>
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

      <div className="border-t border-border p-3 text-[11px] text-text-faint">
        Smart India Hackathon 2026 · PS 26156
      </div>
    </aside>
  );
}
