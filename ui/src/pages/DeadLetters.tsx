import { useMemo, useState } from "react";

import {
  useDlqList,
  useDlqReplay,
  useDlqStats,
  useSuggestParserFromDlqReason,
} from "../api/hooks";
import SourceEditor from "../components/sources/SourceEditor";
import Toast from "../components/Toast";
import DeadLetterTable from "../components/dlq/DeadLetterTable";
import ReasonGroups from "../components/dlq/ReasonGroups";
import Pagination from "../components/events/Pagination";

interface Draft {
  yaml: string;
  sampleLines: string[];
}

export default function DeadLetters() {
  const [reasonFilter, setReasonFilter] = useState<string | null>(null);
  const [unresolvedOnly, setUnresolvedOnly] = useState(false);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(50);
  const [draft, setDraft] = useState<Draft | null>(null);
  const [toast, setToast] = useState<{ message: string; tone: "ok" | "bad" } | null>(null);

  const listParams = useMemo(
    () => ({
      page,
      page_size: pageSize,
      reason: reasonFilter ?? undefined,
      unresolved_only: unresolvedOnly || undefined,
    }),
    [page, pageSize, reasonFilter, unresolvedOnly],
  );

  const statsQuery = useDlqStats(true);
  const listQuery = useDlqList(listParams, true);
  const replay = useDlqReplay();
  const suggest = useSuggestParserFromDlqReason();

  const [replayingReason, setReplayingReason] = useState<string | null>(null);
  const [suggestingReason, setSuggestingReason] = useState<string | null>(null);

  const handleReplay = (reason: string) => {
    setReplayingReason(reason);
    replay.mutate(
      { reason },
      {
        onSuccess: (report) => {
          setReplayingReason(null);
          setToast({
            message: `Replayed ${report.candidates} · ${report.succeeded} recovered · ${report.still_failing} still failing`,
            tone: report.succeeded > 0 ? "ok" : "bad",
          });
        },
        onError: () => {
          setReplayingReason(null);
          setToast({ message: `Replay failed for "${reason}".`, tone: "bad" });
        },
      },
    );
  };

  const handleSuggest = (reason: string) => {
    setSuggestingReason(reason);
    suggest.mutate(reason, {
      onSuccess: (result) => {
        setSuggestingReason(null);
        setDraft({ yaml: result.yaml, sampleLines: result.sampleLines });
      },
      onError: (err) => {
        setSuggestingReason(null);
        setToast({
          message: err instanceof Error ? `Could not suggest a parser: ${err.message}` : "Suggestion failed.",
          tone: "bad",
        });
      },
    });
  };

  return (
    <div className="space-y-5">
      <div className="flex items-end justify-between gap-4">
        <div>
          <h1 className="text-lg font-semibold text-text">Dead Letters</h1>
          <p className="text-sm text-text-faint">
            Nothing is dropped silently. Every failure lands here, raw bytes intact, ready to replay.
          </p>
        </div>
        <label className="flex items-center gap-2 text-sm text-text-muted">
          <input
            type="checkbox"
            checked={unresolvedOnly}
            onChange={(e) => {
              setUnresolvedOnly(e.target.checked);
              setPage(1);
            }}
            className="accent-accent"
          />
          Unresolved only
        </label>
      </div>

      <ReasonGroups
        byReason={statsQuery.data?.by_reason}
        total={statsQuery.data?.total}
        unresolved={statsQuery.data?.unresolved}
        loading={statsQuery.isLoading}
        activeReason={reasonFilter}
        replayingReason={replayingReason}
        suggestingReason={suggestingReason}
        onSelectReason={(r) => {
          setReasonFilter(r);
          setPage(1);
        }}
        onReplay={handleReplay}
        onSuggest={handleSuggest}
      />

      <DeadLetterTable items={listQuery.data?.items} loading={listQuery.isLoading} />

      <Pagination
        page={page}
        pageSize={pageSize}
        total={listQuery.data?.total ?? 0}
        onPageChange={setPage}
        onPageSizeChange={(size) => {
          setPageSize(size);
          setPage(1);
        }}
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
