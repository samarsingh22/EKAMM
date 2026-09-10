import { ChevronLeft, ChevronRight } from "lucide-react";

const PAGE_SIZE_OPTIONS = [25, 50, 100, 250];

interface PaginationProps {
  page: number;
  pageSize: number;
  total: number;
  onPageChange: (page: number) => void;
  onPageSizeChange: (pageSize: number) => void;
}

export default function Pagination({ page, pageSize, total, onPageChange, onPageSizeChange }: PaginationProps) {
  const lastPage = Math.max(1, Math.ceil(total / pageSize));
  const from = total === 0 ? 0 : (page - 1) * pageSize + 1;
  const to = Math.min(total, page * pageSize);

  return (
    <div className="flex flex-wrap items-center justify-between gap-3 text-sm text-text-muted">
      <div>
        Showing <span className="font-medium text-text">{from.toLocaleString()}</span>–
        <span className="font-medium text-text">{to.toLocaleString()}</span> of{" "}
        <span className="font-medium text-text">{total.toLocaleString()}</span>
      </div>

      <div className="flex items-center gap-3">
        <label className="flex items-center gap-2">
          <span className="text-xs uppercase tracking-wide text-text-faint">Rows</span>
          <select
            value={pageSize}
            onChange={(e) => onPageSizeChange(Number(e.target.value))}
            className="rounded-md border border-border bg-bg-inset px-2 py-1 text-sm text-text focus:border-accent focus:outline-none"
          >
            {PAGE_SIZE_OPTIONS.map((n) => (
              <option key={n} value={n}>
                {n}
              </option>
            ))}
          </select>
        </label>

        <div className="flex items-center gap-1">
          <button
            type="button"
            disabled={page <= 1}
            onClick={() => onPageChange(page - 1)}
            className="rounded-md border border-border p-1.5 disabled:cursor-not-allowed disabled:opacity-40 enabled:hover:bg-bg-elevated"
          >
            <ChevronLeft className="h-4 w-4" />
          </button>
          <span className="px-2 font-mono text-xs">
            {page} / {lastPage}
          </span>
          <button
            type="button"
            disabled={page >= lastPage}
            onClick={() => onPageChange(page + 1)}
            className="rounded-md border border-border p-1.5 disabled:cursor-not-allowed disabled:opacity-40 enabled:hover:bg-bg-elevated"
          >
            <ChevronRight className="h-4 w-4" />
          </button>
        </div>
      </div>
    </div>
  );
}
