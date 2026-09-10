import type { ReactNode } from "react";
import { Search, X } from "lucide-react";

import { classLabel } from "../../lib/ocsf";

export interface EventFilterState {
  sourceType: string;
  classUid: string;
  actionId: string;
  srcIp: string;
  dstIp: string;
  timePreset: TimePreset;
  q: string;
}

export type TimePreset = "all" | "15m" | "1h" | "6h" | "24h" | "7d";

export const EMPTY_FILTERS: EventFilterState = {
  sourceType: "",
  classUid: "",
  actionId: "",
  srcIp: "",
  dstIp: "",
  timePreset: "all",
  q: "",
};

const CLASS_OPTIONS = [4001, 4002, 4003, 2004];
const TIME_OPTIONS: { value: TimePreset; label: string }[] = [
  { value: "all", label: "All time" },
  { value: "15m", label: "Last 15 min" },
  { value: "1h", label: "Last hour" },
  { value: "6h", label: "Last 6 hours" },
  { value: "24h", label: "Last 24 hours" },
  { value: "7d", label: "Last 7 days" },
];

interface FilterBarProps {
  value: EventFilterState;
  onChange: (patch: Partial<EventFilterState>) => void;
  sourceOptions: string[];
}

export default function FilterBar({ value, onChange, sourceOptions }: FilterBarProps) {
  const hasActiveFilters = JSON.stringify(value) !== JSON.stringify(EMPTY_FILTERS);

  return (
    <div className="flex flex-wrap items-end gap-3 rounded-lg border border-border bg-bg-panel p-3">
      <Field label="Source">
        <Select
          value={value.sourceType}
          onChange={(v) => onChange({ sourceType: v })}
          options={[{ value: "", label: "All sources" }, ...sourceOptions.map((s) => ({ value: s, label: s }))]}
        />
      </Field>

      <Field label="Class">
        <Select
          value={value.classUid}
          onChange={(v) => onChange({ classUid: v })}
          options={[
            { value: "", label: "All classes" },
            ...CLASS_OPTIONS.map((c) => ({ value: String(c), label: classLabel(c) })),
          ]}
        />
      </Field>

      <Field label="Action">
        <Select
          value={value.actionId}
          onChange={(v) => onChange({ actionId: v })}
          options={[
            { value: "", label: "Any action" },
            { value: "1", label: "Allowed" },
            { value: "2", label: "Denied" },
          ]}
        />
      </Field>

      <Field label="Src IP">
        <input
          value={value.srcIp}
          onChange={(e) => onChange({ srcIp: e.target.value })}
          placeholder="203.0.113.5"
          className="w-32 rounded-md border border-border bg-bg-inset px-2.5 py-1.5 font-mono text-sm text-text placeholder:text-text-faint focus:border-accent focus:outline-none"
        />
      </Field>

      <Field label="Dst IP">
        <input
          value={value.dstIp}
          onChange={(e) => onChange({ dstIp: e.target.value })}
          placeholder="198.51.100.9"
          className="w-32 rounded-md border border-border bg-bg-inset px-2.5 py-1.5 font-mono text-sm text-text placeholder:text-text-faint focus:border-accent focus:outline-none"
        />
      </Field>

      <Field label="Time range">
        <Select
          value={value.timePreset}
          onChange={(v) => onChange({ timePreset: v as TimePreset })}
          options={TIME_OPTIONS}
        />
      </Field>

      <Field label="Free text" className="min-w-[14rem] flex-1">
        <div className="relative">
          <Search className="pointer-events-none absolute left-2.5 top-1/2 h-4 w-4 -translate-y-1/2 text-text-faint" />
          <input
            value={value.q}
            onChange={(e) => onChange({ q: e.target.value })}
            placeholder="search unmapped fields, enrichments…"
            className="w-full rounded-md border border-border bg-bg-inset py-1.5 pl-8 pr-2.5 text-sm text-text placeholder:text-text-faint focus:border-accent focus:outline-none"
          />
        </div>
      </Field>

      {hasActiveFilters && (
        <button
          type="button"
          onClick={() => onChange(EMPTY_FILTERS)}
          className="flex items-center gap-1.5 rounded-md border border-border px-3 py-1.5 text-sm text-text-muted hover:bg-bg-elevated hover:text-text"
        >
          <X className="h-3.5 w-3.5" />
          Clear
        </button>
      )}
    </div>
  );
}

function Field({
  label,
  children,
  className,
}: {
  label: string;
  children: ReactNode;
  className?: string;
}) {
  return (
    <label className={`flex flex-col gap-1 ${className ?? ""}`}>
      <span className="text-[11px] font-medium uppercase tracking-wide text-text-faint">{label}</span>
      {children}
    </label>
  );
}

function Select({
  value,
  onChange,
  options,
}: {
  value: string;
  onChange: (v: string) => void;
  options: { value: string; label: string }[];
}) {
  return (
    <select
      value={value}
      onChange={(e) => onChange(e.target.value)}
      className="rounded-md border border-border bg-bg-inset px-2.5 py-1.5 text-sm text-text focus:border-accent focus:outline-none"
    >
      {options.map((o) => (
        <option key={o.value} value={o.value}>
          {o.label}
        </option>
      ))}
    </select>
  );
}
