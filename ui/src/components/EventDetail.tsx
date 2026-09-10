import { useEffect, useState } from "react";
import { X, Braces, FileText, Link2, Columns2 } from "lucide-react";
import clsx from "clsx";

import NormalizedTab from "./event-detail/NormalizedTab";
import RawTab from "./event-detail/RawTab";
import LineageTab from "./event-detail/LineageTab";
import SplitView from "./event-detail/SplitView";

type Tab = "normalized" | "raw" | "lineage";

const TABS: { id: Tab; label: string; icon: typeof Braces }[] = [
  { id: "normalized", label: "Normalized", icon: Braces },
  { id: "raw", label: "Raw", icon: FileText },
  { id: "lineage", label: "Lineage", icon: Link2 },
];

interface EventDetailProps {
  /** `null`/`undefined` -> the panel renders nothing (but stays mounted, so it can animate in later). */
  eventUid: string | null | undefined;
  onClose: () => void;
}

/**
 * The event detail slide-over: three tabs (Normalized / Raw / Lineage) plus a
 * prominent Split View toggle that replaces the tabbed content with the
 * raw-vs-normalized side-by-side view (`SplitView`) — the demo's 0:35-0:55
 * shot.
 */
export default function EventDetail({ eventUid, onClose }: EventDetailProps) {
  const [tab, setTab] = useState<Tab>("normalized");
  const [split, setSplit] = useState(false);
  const [entered, setEntered] = useState(false);

  const open = Boolean(eventUid);

  useEffect(() => {
    if (!open) {
      setEntered(false);
      return;
    }
    const raf = requestAnimationFrame(() => setEntered(true));
    return () => cancelAnimationFrame(raf);
  }, [open]);

  // fresh tab/split state each time a *different* event is opened
  useEffect(() => {
    if (open) {
      setTab("normalized");
      setSplit(false);
    }
  }, [eventUid, open]);

  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, onClose]);

  if (!eventUid) return null;

  return (
    <div className="fixed inset-0 z-50 flex justify-end">
      <div
        className={clsx(
          "absolute inset-0 bg-black/60 transition-opacity duration-300",
          entered ? "opacity-100" : "opacity-0",
        )}
        onClick={onClose}
        aria-hidden
      />

      <div
        className={clsx(
          "relative flex h-full w-full flex-col border-l border-border bg-bg-panel shadow-2xl transition-transform duration-300 ease-out",
          split ? "max-w-6xl" : "max-w-3xl",
          entered ? "translate-x-0" : "translate-x-full",
        )}
      >
        {/* header */}
        <div className="flex shrink-0 flex-col gap-3 border-b border-border px-5 py-4">
          <div className="flex items-center justify-between gap-3">
            <div className="min-w-0">
              <div className="text-[11px] uppercase tracking-wider text-text-faint">Event</div>
              <div className="truncate font-mono text-sm text-text" title={eventUid}>
                {eventUid}
              </div>
            </div>
            <button
              type="button"
              onClick={onClose}
              className="shrink-0 rounded-md p-1.5 text-text-muted hover:bg-bg-elevated hover:text-text"
              aria-label="Close"
            >
              <X className="h-5 w-5" />
            </button>
          </div>

          <div className="flex items-center justify-between gap-3">
            <nav className="flex gap-1">
              {TABS.map(({ id, label, icon: Icon }) => (
                <button
                  key={id}
                  type="button"
                  onClick={() => setTab(id)}
                  disabled={split}
                  className={clsx(
                    "flex items-center gap-1.5 rounded-md px-3 py-1.5 text-sm font-medium transition-colors",
                    split
                      ? "cursor-not-allowed text-text-faint"
                      : tab === id
                        ? "bg-accent-bg text-accent"
                        : "text-text-muted hover:bg-bg-elevated hover:text-text",
                  )}
                >
                  <Icon className="h-4 w-4" strokeWidth={2} />
                  {label}
                </button>
              ))}
            </nav>

            <button
              type="button"
              onClick={() => setSplit((v) => !v)}
              className={clsx(
                "flex shrink-0 items-center gap-2 rounded-md border px-3 py-1.5 text-sm font-semibold transition-colors",
                split
                  ? "border-accent bg-accent text-bg"
                  : "border-accent text-accent hover:bg-accent-bg",
              )}
            >
              <Columns2 className="h-4 w-4" strokeWidth={2.5} />
              Split View
            </button>
          </div>
        </div>

        {/* content */}
        <div className="min-h-0 flex-1 overflow-hidden">
          {split ? (
            <SplitView eventUid={eventUid} />
          ) : (
            <div className="h-full overflow-y-auto">
              {tab === "normalized" && <NormalizedTab eventUid={eventUid} />}
              {tab === "raw" && <RawTab eventUid={eventUid} />}
              {tab === "lineage" && <LineageTab eventUid={eventUid} />}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
