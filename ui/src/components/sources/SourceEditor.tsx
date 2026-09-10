import { useEffect, useMemo, useState } from "react";
import { X, Sparkles, Save, Loader2, AlertTriangle } from "lucide-react";
import clsx from "clsx";

import {
  useGenerateSourceSuggestion,
  useTestSource,
  useValidateSourceYaml,
  useWriteSource,
} from "../../api/hooks";
import YamlEditor from "./YamlEditor";
import TestPreview from "./TestPreview";
import { useDebouncedValue } from "../../lib/useDebouncedValue";

const BLANK_TEMPLATE = `name: my_new_source
version: "0.1.0"
vendor: Unknown
product: Unknown
product_version: unknown

detect:
  contains: "CHANGE_ME"

parse:
  envelope: none
  engine: kv
  options: {}

normalize:
  class_uid: 4001
  category_uid: 4
  activity_id: 6
  constants:
    metadata.product.vendor_name: Unknown
    metadata.product.name: Unknown
    severity_id: 1
  fields: {}
  unmapped: keep_all

validate:
  required: [class_uid, category_uid]
  on_failure: dead_letter
`;

function splitLines(text: string): string[] {
  return text
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean);
}

interface SourceEditorProps {
  /** `null` -> "Add New Source"; otherwise editing an existing source. */
  initial: { name: string; yaml: string } | null;
  /** Pre-fill a *new* source's YAML (e.g. from the Templates page's "Generate Parser"). Ignored when `initial` is set. */
  draftYaml?: string;
  /** Pre-fill the sample-lines pane alongside `draftYaml`. */
  draftSampleLines?: string[];
  onClose: () => void;
  onSaved: (name: string) => void;
}

/**
 * The full-screen source editor: YAML on the left, sample lines + live
 * preview on the right. "Save & Activate" PUTs the definition, which hot-
 * reloads the live registry with no restart — the reload counter ticking up
 * in the top bar (see `TopBar.tsx`) is the visible proof.
 */
export default function SourceEditor({
  initial,
  draftYaml,
  draftSampleLines,
  onClose,
  onSaved,
}: SourceEditorProps) {
  const [yamlText, setYamlText] = useState(initial?.yaml ?? draftYaml ?? BLANK_TEMPLATE);
  const [sampleLinesText, setSampleLinesText] = useState(draftSampleLines?.join("\n") ?? "");
  const [generateSourceId, setGenerateSourceId] = useState(initial?.name ?? "new-source");

  const debouncedYaml = useDebouncedValue(yamlText, 500);
  const debouncedSamples = useDebouncedValue(sampleLinesText, 500);
  const sampleLines = useMemo(() => splitLines(debouncedSamples), [debouncedSamples]);

  const validate = useValidateSourceYaml();
  const test = useTestSource();
  const generate = useGenerateSourceSuggestion();
  const write = useWriteSource();

  useEffect(() => {
    if (debouncedYaml.trim()) validate.mutate(debouncedYaml);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [debouncedYaml]);

  useEffect(() => {
    if (debouncedYaml.trim() && sampleLines.length > 0) {
      test.mutate({ yamlText: debouncedYaml, sampleLines });
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [debouncedYaml, sampleLines.join("\n")]);

  useEffect(() => {
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape") onClose();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const handleGenerate = () => {
    const lines = splitLines(sampleLinesText);
    if (lines.length === 0) return;
    generate.mutate(
      { source_id: generateSourceId || "new-source", sample_lines: lines },
      { onSuccess: (res) => setYamlText(res.yaml) },
    );
  };

  const handleSave = () => {
    const name = validate.data?.name;
    if (!name || !validate.data?.valid) return;
    write.mutate({ name, yamlText }, { onSuccess: () => onSaved(name) });
  };

  const canSave = Boolean(validate.data?.valid && validate.data?.name) && !write.isPending;

  return (
    <div className="fixed inset-0 z-50 flex flex-col bg-bg">
      {/* header */}
      <div className="flex shrink-0 items-center justify-between gap-4 border-b border-border bg-bg-panel px-5 py-3">
        <div className="flex min-w-0 items-center gap-3">
          <button
            type="button"
            onClick={onClose}
            className="rounded-md p-1.5 text-text-muted hover:bg-bg-elevated hover:text-text"
            aria-label="Close"
          >
            <X className="h-5 w-5" />
          </button>
          <div>
            <h1 className="text-sm font-semibold text-text">
              {initial ? `Edit source — ${initial.name}` : "Add New Source"}
            </h1>
            <p className="text-xs text-text-faint">
              {validate.data?.valid ? (
                <span className="text-status-ok">valid — {validate.data.name}</span>
              ) : validate.data && !validate.data.valid ? (
                <span className="text-status-bad">
                  {validate.data.errors.length} validation error{validate.data.errors.length === 1 ? "" : "s"}
                </span>
              ) : (
                "validating…"
              )}
            </p>
          </div>
        </div>

        <div className="flex shrink-0 items-center gap-2">
          {write.isError && (
            <span className="flex items-center gap-1 text-xs text-status-bad">
              <AlertTriangle className="h-3.5 w-3.5" /> save failed
            </span>
          )}
          <button
            type="button"
            onClick={handleSave}
            disabled={!canSave}
            className={clsx(
              "flex items-center gap-2 rounded-md px-4 py-2 text-sm font-semibold transition-colors",
              canSave
                ? "bg-accent text-bg hover:bg-accent/90"
                : "cursor-not-allowed bg-bg-elevated text-text-faint",
            )}
          >
            {write.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Save className="h-4 w-4" />}
            Save & Activate
          </button>
        </div>
      </div>

      {/* body */}
      <div className="grid min-h-0 flex-1 grid-cols-1 divide-y divide-border lg:grid-cols-2 lg:divide-x lg:divide-y-0">
        {/* left: yaml editor */}
        <div className="flex min-h-0 flex-col">
          <div className="flex shrink-0 items-center justify-between border-b border-border bg-bg-panel px-4 py-2">
            <span className="text-xs font-semibold uppercase tracking-wider text-text-muted">
              Source definition (YAML)
            </span>
          </div>
          <div className="min-h-0 flex-1">
            <YamlEditor value={yamlText} onChange={setYamlText} errors={validate.data?.errors ?? []} />
          </div>
          {validate.data && !validate.data.valid && (
            <div className="max-h-32 shrink-0 overflow-y-auto border-t border-border bg-bg-inset p-3">
              {validate.data.errors.map((err, i) => (
                <div key={i} className="text-xs text-status-bad">
                  {err}
                </div>
              ))}
            </div>
          )}
        </div>

        {/* right: samples + preview */}
        <div className="flex min-h-0 flex-col">
          <div className="flex shrink-0 flex-col gap-2 border-b border-border bg-bg-panel px-4 py-2.5">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold uppercase tracking-wider text-text-muted">
                Sample log lines
              </span>
              <div className="flex items-center gap-2">
                <input
                  value={generateSourceId}
                  onChange={(e) => setGenerateSourceId(e.target.value)}
                  placeholder="source_id"
                  className="w-28 rounded-md border border-border bg-bg-inset px-2 py-1 font-mono text-xs text-text placeholder:text-text-faint focus:border-accent focus:outline-none"
                />
                <button
                  type="button"
                  onClick={handleGenerate}
                  disabled={generate.isPending || splitLines(sampleLinesText).length === 0}
                  className="flex items-center gap-1.5 rounded-md border border-accent px-3 py-1.5 text-xs font-semibold text-accent transition-colors hover:bg-accent-bg disabled:cursor-not-allowed disabled:border-border disabled:text-text-faint"
                >
                  {generate.isPending ? (
                    <Loader2 className="h-3.5 w-3.5 animate-spin" />
                  ) : (
                    <Sparkles className="h-3.5 w-3.5" />
                  )}
                  Generate from samples
                </button>
              </div>
            </div>
            {generate.isError && (
              <p className="text-xs text-status-bad">
                {generate.error instanceof Error ? generate.error.message : "generation failed"}
              </p>
            )}
          </div>

          <textarea
            value={sampleLinesText}
            onChange={(e) => setSampleLinesText(e.target.value)}
            placeholder={"one raw log line per line…\n<190>Sep 12 08:00:00 host app: conn 10.0.0.1:51000 to 198.51.100.9:443 tcp allow"}
            spellCheck={false}
            className="h-40 shrink-0 resize-none border-b border-border bg-bg-inset p-3 font-mono text-xs text-text placeholder:text-text-faint focus:outline-none"
          />

          <div className="min-h-0 flex-1 overflow-y-auto">
            <TestPreview
              result={test.data}
              loading={test.isPending}
              errorMessage={test.isError ? "Preview failed — check the YAML is valid first." : null}
              hasInput={sampleLines.length > 0 && Boolean(debouncedYaml.trim())}
            />
          </div>
        </div>
      </div>
    </div>
  );
}

