import clsx from "clsx";

interface ScoreBarProps {
  label: string;
  value: number | null | undefined; // 0..1
}

function toneFor(value: number): "ok" | "warn" | "bad" {
  if (value >= 0.9) return "ok";
  if (value >= 0.6) return "warn";
  return "bad";
}

const BAR_TONE = {
  ok: "bg-status-ok",
  warn: "bg-status-warn",
  bad: "bg-status-bad",
};

const TEXT_TONE = {
  ok: "text-status-ok",
  warn: "text-status-warn",
  bad: "text-status-bad",
};

/** A labeled, colour-graded horizontal bar for a 0..1 score (parse rate, completeness, ...). */
export default function ScoreBar({ label, value }: ScoreBarProps) {
  const pct = value !== null && value !== undefined ? Math.round(value * 100) : null;
  const tone = pct !== null ? toneFor(pct / 100) : "bad";

  return (
    <div>
      <div className="mb-1 flex items-center justify-between text-xs">
        <span className="font-medium uppercase tracking-wide text-text-faint">{label}</span>
        <span className={clsx("font-mono font-semibold", pct !== null && TEXT_TONE[tone])}>
          {pct !== null ? `${pct}%` : "—"}
        </span>
      </div>
      <div className="h-2 w-full overflow-hidden rounded-full bg-bg-inset">
        <div
          className={clsx("h-full rounded-full transition-all duration-300", pct !== null && BAR_TONE[tone])}
          style={{ width: `${pct ?? 0}%` }}
        />
      </div>
    </div>
  );
}
