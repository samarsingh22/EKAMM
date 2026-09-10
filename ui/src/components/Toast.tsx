import { useEffect } from "react";
import { AlertTriangle, CheckCircle2, X } from "lucide-react";
import clsx from "clsx";

interface ToastProps {
  message: string;
  onDismiss: () => void;
  durationMs?: number;
  tone?: "ok" | "bad";
}

/** A single, dismissible, auto-expiring toast — bottom-center, high-contrast. */
export default function Toast({ message, onDismiss, durationMs = 5000, tone = "ok" }: ToastProps) {
  useEffect(() => {
    const id = setTimeout(onDismiss, durationMs);
    return () => clearTimeout(id);
  }, [onDismiss, durationMs]);

  return (
    <div
      className={clsx(
        "fixed bottom-6 left-1/2 z-[60] flex -translate-x-1/2 items-center gap-3 rounded-lg border bg-bg-elevated px-4 py-3 shadow-2xl",
        tone === "ok" ? "border-status-ok/40" : "border-status-bad/40",
        "animate-toast-in",
      )}
    >
      {tone === "ok" ? (
        <CheckCircle2 className="h-5 w-5 shrink-0 text-status-ok" strokeWidth={2} />
      ) : (
        <AlertTriangle className="h-5 w-5 shrink-0 text-status-bad" strokeWidth={2} />
      )}
      <span className="text-sm font-medium text-text">{message}</span>
      <button
        type="button"
        onClick={onDismiss}
        className="ml-2 shrink-0 rounded p-0.5 text-text-faint hover:text-text"
        aria-label="Dismiss"
      >
        <X className="h-4 w-4" />
      </button>
    </div>
  );
}
