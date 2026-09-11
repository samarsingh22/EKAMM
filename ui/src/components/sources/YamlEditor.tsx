import { useEffect, useMemo, useRef } from "react";
import CodeMirror, { type ReactCodeMirrorRef } from "@uiw/react-codemirror";
import { yaml as yamlLang } from "@codemirror/lang-yaml";
import { linter, lintGutter, forceLinting, type Diagnostic } from "@codemirror/lint";

interface YamlEditorProps {
  value: string;
  onChange: (value: string) => void;
  /** `ValidateResponse.errors` — `"loc: message"` strings (no source position). */
  errors: string[];
}

function escapeRegExp(text: string): string {
  return text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * Best-effort positioning: `POST /sources/validate` reports errors as
 * `"<dotted.path>: <message>"` with no line/column (pydantic's error
 * location, not a text offset). Heuristic: take the path's last segment
 * (e.g. "class_uid" from "normalize.class_uid") and find the first line that
 * looks like that YAML key; fall back to underlining the whole document so
 * no error is ever silently un-shown.
 */
function buildDiagnostics(doc: string, errors: string[]): Diagnostic[] {
  const lines = doc.split("\n");
  return errors.map((message) => {
    const [locPart] = message.split(":");
    const lastSegment = locPart?.trim().split(".").pop();
    const lineIndex =
      lastSegment && lastSegment !== "<root>"
        ? lines.findIndex((line) => new RegExp(`^\\s*${escapeRegExp(lastSegment)}\\s*:`).test(line))
        : -1;

    if (lineIndex === -1) {
      return { from: 0, to: doc.length, severity: "error", message };
    }
    const from = lines.slice(0, lineIndex).reduce((acc, line) => acc + line.length + 1, 0);
    return { from, to: from + lines[lineIndex].length, severity: "error", message };
  });
}

/** A light, syntax-highlighted YAML editor with inline lint markers driven by external validation errors. */
export default function YamlEditor({ value, onChange, errors }: YamlEditorProps) {
  const editorRef = useRef<ReactCodeMirrorRef>(null);
  const errorsRef = useRef<string[]>(errors);

  useEffect(() => {
    errorsRef.current = errors;
    if (editorRef.current?.view) {
      forceLinting(editorRef.current.view);
    }
  }, [errors]);

  // built once - reconfiguring extensions on every keystroke would thrash editor state
  const extensions = useMemo(
    () => [
      yamlLang(),
      lintGutter(),
      linter((view) => buildDiagnostics(view.state.doc.toString(), errorsRef.current)),
    ],
    [],
  );

  return (
    <CodeMirror
      ref={editorRef}
      value={value}
      onChange={onChange}
      height="100%"
      theme="light"
      extensions={extensions}
      basicSetup={{ foldGutter: true, autocompletion: false }}
      className="h-full overflow-hidden text-sm [&_.cm-editor]:h-full [&_.cm-scroller]:font-mono"
    />
  );
}
