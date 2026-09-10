import type { PropsWithChildren } from "react";
import clsx from "clsx";

import type { Tone } from "../lib/ocsf";

const TONE_CLASSES: Record<Tone, string> = {
  ok: "bg-status-ok/15 text-status-ok",
  warn: "bg-status-warn/15 text-status-warn",
  bad: "bg-status-bad/15 text-status-bad",
  muted: "bg-bg-elevated text-text-muted",
};

export default function Badge({ tone = "muted", children }: PropsWithChildren<{ tone?: Tone }>) {
  return (
    <span
      className={clsx(
        "inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium whitespace-nowrap",
        TONE_CLASSES[tone],
      )}
    >
      {children}
    </span>
  );
}
