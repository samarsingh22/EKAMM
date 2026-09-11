import { useState } from "react";
import { ChevronDown, ChevronRight } from "lucide-react";
import clsx from "clsx";

interface JsonTreeProps {
  data: unknown;
  /** Nodes at this depth or shallower start expanded; deeper nodes start collapsed. */
  defaultExpandDepth?: number;
  depth?: number;
  /** Rendered before the value on this line, e.g. `"metadata":` — omitted at the root. */
  fieldKey?: string;
  /** Trailing comma-equivalent; purely cosmetic, omitted on the last sibling. */
  trailingComma?: boolean;
}

/**
 * A collapsible, syntax-highlighted JSON tree — no external dependency, just
 * recursive Tailwind-styled spans. Objects/arrays are expandable; every other
 * value type gets its own color so the OCSF record reads at a glance.
 */
export default function JsonTree({
  data,
  defaultExpandDepth = 1,
  depth = 0,
  fieldKey,
  trailingComma = false,
}: JsonTreeProps) {
  const isObject = data !== null && typeof data === "object" && !Array.isArray(data);
  const isArray = Array.isArray(data);

  if (isObject || isArray) {
    return (
      <Collapsible
        data={data as Record<string, unknown> | unknown[]}
        isArray={isArray}
        depth={depth}
        defaultExpandDepth={defaultExpandDepth}
        fieldKey={fieldKey}
        trailingComma={trailingComma}
      />
    );
  }

  return (
    <div className="whitespace-pre" style={{ paddingLeft: depth === 0 ? 0 : undefined }}>
      <Key fieldKey={fieldKey} />
      <Scalar value={data} />
      {trailingComma && <span className="text-text-faint">,</span>}
    </div>
  );
}

function Key({ fieldKey }: { fieldKey?: string }) {
  if (fieldKey === undefined) return null;
  return (
    <>
      <span className="text-sky-700">"{fieldKey}"</span>
      <span className="text-text-faint">: </span>
    </>
  );
}

function Scalar({ value }: { value: unknown }) {
  if (value === null) return <span className="text-text-faint">null</span>;
  if (typeof value === "string") return <span className="text-emerald-700">"{value}"</span>;
  if (typeof value === "number") return <span className="text-amber-700">{value}</span>;
  if (typeof value === "boolean") return <span className="text-violet-700">{String(value)}</span>;
  return <span className="text-text-muted">{String(value)}</span>;
}

interface CollapsibleProps {
  data: Record<string, unknown> | unknown[];
  isArray: boolean;
  depth: number;
  defaultExpandDepth: number;
  fieldKey?: string;
  trailingComma: boolean;
}

function Collapsible({ data, isArray, depth, defaultExpandDepth, fieldKey, trailingComma }: CollapsibleProps) {
  const entries = isArray
    ? (data as unknown[]).map((v, i) => [String(i), v] as const)
    : Object.entries(data as Record<string, unknown>);
  const [open, setOpen] = useState(depth < defaultExpandDepth);
  const openBrace = isArray ? "[" : "{";
  const closeBrace = isArray ? "]" : "}";

  if (entries.length === 0) {
    return (
      <div className="whitespace-pre">
        <Key fieldKey={fieldKey} />
        <span className="text-text-faint">
          {openBrace}
          {closeBrace}
        </span>
        {trailingComma && <span className="text-text-faint">,</span>}
      </div>
    );
  }

  return (
    <div>
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="inline-flex items-center gap-0.5 whitespace-pre text-left hover:bg-bg-elevated"
      >
        {open ? (
          <ChevronDown className="h-3 w-3 shrink-0 text-text-faint" />
        ) : (
          <ChevronRight className="h-3 w-3 shrink-0 text-text-faint" />
        )}
        <Key fieldKey={fieldKey} />
        <span className="text-text-faint">{openBrace}</span>
        {!open && (
          <span className="text-text-faint">
            {" "}
            {entries.length} {isArray ? "items" : "keys"} {closeBrace}
          </span>
        )}
      </button>

      {open && (
        <div className={clsx("border-l border-border-subtle pl-3", depth === 0 && "border-l-0 pl-4")}>
          {entries.map(([key, value], i) => (
            <JsonTree
              key={key}
              data={value}
              depth={depth + 1}
              defaultExpandDepth={defaultExpandDepth}
              fieldKey={isArray ? undefined : key}
              trailingComma={i < entries.length - 1}
            />
          ))}
          <div className="whitespace-pre text-text-faint">{closeBrace}</div>
        </div>
      )}
    </div>
  );
}
