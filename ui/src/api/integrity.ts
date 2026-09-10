import { api, toQueryString } from "./client";
import type {
  ChainVerifyReport,
  EventProofOut,
  EventsVerifyReport,
  IntegrityStatus,
  LedgerEntryRow,
} from "./types";

/** `/api/v1/integrity` — see `ulpf/api/routes/integrity.py`. */
export const integrityApi = {
  status: (): Promise<IntegrityStatus> => api.get("/integrity/status"),

  ledger: (): Promise<LedgerEntryRow[]> => api.get("/integrity/ledger"),

  verifyChain: (): Promise<ChainVerifyReport> => api.post("/integrity/verify/chain"),

  verifyEvents: (date?: string): Promise<EventsVerifyReport> =>
    api.post(`/integrity/verify/events${toQueryString({ date })}`),

  proof: (eventUid: string): Promise<EventProofOut> =>
    api.get(`/integrity/proof/${encodeURIComponent(eventUid)}`),
};
