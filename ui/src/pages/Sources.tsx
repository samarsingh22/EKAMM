import { useState } from "react";
import { Loader2, Plus, Radio } from "lucide-react";

import { useSourceDetail, useSourcesList } from "../api/hooks";
import PagePlaceholder from "../components/PagePlaceholder";
import Skeleton from "../components/Skeleton";
import Toast from "../components/Toast";
import SourceCard from "../components/sources/SourceCard";
import SourceEditor from "../components/sources/SourceEditor";

type EditorTarget = "new" | string | null;

export default function Sources() {
  const [editing, setEditing] = useState<EditorTarget>(null);
  const [toast, setToast] = useState<string | null>(null);

  const sourcesQuery = useSourcesList(true);
  const editingExisting = typeof editing === "string" ? editing : undefined;
  const detailQuery = useSourceDetail(editingExisting);

  const handleSaved = (name: string) => {
    setEditing(null);
    setToast(`Source active — no restart required (${name})`);
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-semibold text-text">Sources</h1>
          <p className="text-sm text-text-faint">Loaded source definitions and their live parse health.</p>
        </div>
        <button
          type="button"
          onClick={() => setEditing("new")}
          className="flex items-center gap-2 rounded-md bg-accent px-4 py-2 text-sm font-semibold text-bg transition-colors hover:bg-accent/90"
        >
          <Plus className="h-4 w-4" strokeWidth={2.5} />
          Add New Source
        </button>
      </div>

      {sourcesQuery.isLoading ? (
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-3">
          {Array.from({ length: 6 }).map((_, i) => (
            <Skeleton key={i} className="h-32 w-full" />
          ))}
        </div>
      ) : (sourcesQuery.data ?? []).length === 0 ? (
        <PagePlaceholder
          title="No sources loaded yet"
          description='Click "Add New Source" to onboard your first perimeter log source.'
          icon={Radio}
        />
      ) : (
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-3">
          {(sourcesQuery.data ?? []).map((source) => (
            <SourceCard key={source.name} source={source} onClick={() => setEditing(source.name)} />
          ))}
        </div>
      )}

      {editing === "new" && (
        <SourceEditor initial={null} onClose={() => setEditing(null)} onSaved={handleSaved} />
      )}

      {editingExisting && detailQuery.data && (
        <SourceEditor
          initial={{ name: editingExisting, yaml: detailQuery.data.yaml }}
          onClose={() => setEditing(null)}
          onSaved={handleSaved}
        />
      )}

      {editingExisting && detailQuery.isLoading && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-bg">
          <Loader2 className="h-8 w-8 animate-spin text-accent" />
        </div>
      )}

      {toast && <Toast message={toast} onDismiss={() => setToast(null)} />}
    </div>
  );
}
