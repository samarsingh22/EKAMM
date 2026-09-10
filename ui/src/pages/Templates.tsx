import { useMemo, useState } from "react";

import {
  useGenerateParserFromTemplate,
  useTemplatesDrift,
  useTemplatesList,
  useTemplatesUnknown,
} from "../api/hooks";
import type { TemplateOut } from "../api/types";
import SourceEditor from "../components/sources/SourceEditor";
import Toast from "../components/Toast";
import DriftSection from "../components/templates/DriftSection";
import TemplatesTable from "../components/templates/TemplatesTable";
import UnknownSourcesSection from "../components/templates/UnknownSourcesSection";
import { SPARKLINE_WINDOWS, buildTemplateSparklines, templateKey } from "../lib/templateSparkline";

interface Draft {
  yaml: string;
  sampleLines: string[];
}

export default function Templates() {
  const [driftWindow, setDriftWindow] = useState("1h");
  const [draft, setDraft] = useState<Draft | null>(null);
  const [toast, setToast] = useState<{ message: string; tone: "ok" | "bad" } | null>(null);

  const unknownQuery = useTemplatesUnknown(true);
  const allQuery = useTemplatesList(undefined, true);
  const driftQuery = useTemplatesDrift(driftWindow, undefined, true);

  // fixed-length, explicit hook calls (not a loop) so React's hook order stays stable;
  // one fetch per sparkline window, refreshed on mount rather than live-polled (see lib/templateSparkline).
  const spark0 = useTemplatesDrift(SPARKLINE_WINDOWS[0], undefined, false);
  const spark1 = useTemplatesDrift(SPARKLINE_WINDOWS[1], undefined, false);
  const spark2 = useTemplatesDrift(SPARKLINE_WINDOWS[2], undefined, false);
  const spark3 = useTemplatesDrift(SPARKLINE_WINDOWS[3], undefined, false);
  const spark4 = useTemplatesDrift(SPARKLINE_WINDOWS[4], undefined, false);

  const sparklines = useMemo(
    () => buildTemplateSparklines([spark0.data, spark1.data, spark2.data, spark3.data, spark4.data]),
    [spark0.data, spark1.data, spark2.data, spark3.data, spark4.data],
  );

  const generateParser = useGenerateParserFromTemplate();
  const [generatingKey, setGeneratingKey] = useState<string | null>(null);

  const handleGenerateParser = (template: TemplateOut) => {
    const key = templateKey(template);
    setGeneratingKey(key);
    generateParser.mutate(
      { templateId: template.template_id, sourceId: template.source_id },
      {
        onSuccess: (result) => {
          setGeneratingKey(null);
          setDraft({ yaml: result.yaml, sampleLines: result.sampleLines });
        },
        onError: () => {
          setGeneratingKey(null);
          setToast({ message: `Could not generate a parser for ${template.template_id} — try again.`, tone: "bad" });
        },
      },
    );
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-lg font-semibold text-text">Templates</h1>
        <p className="text-sm text-text-faint">
          Requirement (i): every shape unstructured traffic takes, mined automatically — and how fast it
          becomes a working parser.
        </p>
      </div>

      <UnknownSourcesSection
        templates={unknownQuery.data}
        loading={unknownQuery.isLoading}
        generatingKey={generatingKey}
        onGenerateParser={handleGenerateParser}
      />

      <TemplatesTable
        templates={allQuery.data}
        loading={allQuery.isLoading}
        sparklines={sparklines}
        generatingKey={generatingKey}
        onGenerateParser={handleGenerateParser}
      />

      <DriftSection
        entries={driftQuery.data}
        loading={driftQuery.isLoading}
        window={driftWindow}
        onWindowChange={setDriftWindow}
      />

      {draft && (
        <SourceEditor
          initial={null}
          draftYaml={draft.yaml}
          draftSampleLines={draft.sampleLines}
          onClose={() => setDraft(null)}
          onSaved={(name) => {
            setDraft(null);
            setToast({ message: `Source active — no restart required (${name})`, tone: "ok" });
          }}
        />
      )}

      {toast && <Toast message={toast.message} tone={toast.tone} onDismiss={() => setToast(null)} />}
    </div>
  );
}
