import clsx from "clsx";
import { Link2 } from "lucide-react";

interface LinkChipProps {
  label: string;
  value: string | undefined;
  active: boolean;
  onHover: (hovering: boolean) => void;
  truncate?: boolean;
}

/**
 * A labeled, monospace value chip used to visually connect the raw and
 * normalized panes in split view: hovering this chip *or* its counterpart on
 * the other side (both driven by the same lifted `active` state) lights up
 * both at once, making the raw<->normalized traceability link legible
 * without drawing an actual connector line across the split.
 */
export default function LinkChip({ label, value, active, onHover, truncate = true }: LinkChipProps) {
  return (
    <button
      type="button"
      onMouseEnter={() => onHover(true)}
      onMouseLeave={() => onHover(false)}
      onFocus={() => onHover(true)}
      onBlur={() => onHover(false)}
      className={clsx(
        "flex w-full items-center gap-2 rounded-md border px-2.5 py-1.5 text-left transition-all duration-150",
        active
          ? "border-accent bg-accent-bg ring-2 ring-accent/60"
          : "border-border bg-bg-inset hover:border-accent/50",
      )}
    >
      <Link2 className={clsx("h-3.5 w-3.5 shrink-0", active ? "text-accent" : "text-text-faint")} />
      <span className="shrink-0 text-[11px] uppercase tracking-wide text-text-faint">{label}</span>
      <span
        className={clsx(
          "font-mono text-xs",
          truncate && "overflow-hidden text-ellipsis whitespace-nowrap",
          active ? "text-accent" : "text-text-muted",
        )}
      >
        {value ?? "—"}
      </span>
    </button>
  );
}
