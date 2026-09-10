import type { CSSProperties } from "react";
import clsx from "clsx";

/**
 * A pulsing placeholder block. Every panel on this page renders one of these
 * in place of its real content while loading — the dashboard must never show
 * a blank screen, not even for a frame.
 */
export default function Skeleton({
  className,
  style,
}: {
  className?: string;
  style?: CSSProperties;
}) {
  return <div className={clsx("animate-pulse rounded-md bg-bg-elevated", className)} style={style} />;
}
