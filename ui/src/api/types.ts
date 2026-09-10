/**
 * TypeScript mirrors of the Pydantic response models under `ulpf/api/routes/`.
 *
 * Rows whose shape is genuinely open-ended in the backend (a flattened
 * silver-lake row, a full nested OCSF record) stay as `Record<string, unknown>`
 * with a handful of well-known fields called out — over-typing those would
 * just drift from the real schema (which validate.py itself allows to grow
 * per source) without buying real safety.
 */

// ---------------------------------------------------------------------------
// events.py

/** A flattened silver-lake row: the well-known core columns, plus anything else. */
export interface EventRow {
  event_uid: string;
  time?: number;
  class_uid?: number;
  category_uid?: number;
  severity_id?: number;
  source_type?: string;
  src_ip?: string;
  dst_ip?: string;
  src_port?: number;
  dst_port?: number;
  action_id?: number;
  /** Mapped display name, e.g. "Allowed"/"Denied" — present when the source YAML maps one. */
  action?: string;
  /** Mapped display name for severity_id — filled in by `finalize()`. */
  severity?: string;
  [key: string]: unknown;
}

export interface EventListResponse {
  items: EventRow[];
  total: number;
  page: number;
  page_size: number;
}

export interface EventListParams {
  page?: number;
  page_size?: number;
  source_type?: string;
  class_uid?: number;
  action_id?: number;
  src_ip?: string;
  dst_ip?: string;
  port?: number;
  severity_id?: number;
  time_from?: number;
  time_to?: number;
  q?: string;
}

/** The full normalized OCSF record, unflattened (nested). Shape varies by class_uid. */
export type EventDetail = Record<string, unknown>;

export interface EventRaw {
  event_uid: string;
  raw_b64: string;
  raw_text: string;
  raw_hash: string;
  raw_len: number;
  ingest_time_ns: number;
  source_id: string;
  transport: string;
  verified: boolean;
}

export interface MerkleProofStep {
  sibling: string;
  side: "left" | "right";
}

export interface EventLineage {
  event_uid: string;
  raw_hash: string;
  raw_verified: boolean;
  mapping_version: string | null;
  source_type: string | null;
  ledger_seq: number | null;
  merkle_proof: MerkleProofStep[];
  ledger_verified: boolean;
}

export interface SourceCount {
  source_type: string;
  events: number;
  [key: string]: unknown;
}

export interface ClassCount {
  class_uid: number;
  events: number;
}

export interface ActionCount {
  action_id: number;
  events: number;
}

export interface EventsStatsSummary {
  total_events: number;
  by_source_type: SourceCount[];
  by_class_uid: ClassCount[];
  by_action: ActionCount[];
  parse_success_rate: number | null;
  dlq_total: number;
  dlq_rate: number;
}

export interface TimeseriesPoint {
  bucket: string;
  source_type: string;
  events: number;
}

export interface EventsTimeseries {
  interval: string;
  window: string;
  points: TimeseriesPoint[];
}

// ---------------------------------------------------------------------------
// sources.py

export interface SourceListItem {
  name: string;
  vendor: string;
  product: string;
  version: string;
  enabled: boolean;
  events_seen: number;
  parse_rate: number | null;
  avg_completeness: number | null;
  last_event_ns: number | null;
}

export interface SourceDetail {
  definition: Record<string, unknown>;
  yaml: string;
  path: string | null;
}

export interface ValidateResponse {
  valid: boolean;
  errors: string[];
  name?: string | null;
  vendor?: string | null;
  product?: string | null;
  version?: string | null;
  class_uid?: number | null;
}

export interface SourceTestResult {
  line: string;
  matched_detect: boolean;
  ocsf: Record<string, unknown> | null;
  valid: boolean | null;
  completeness: number | null;
  error: string | null;
}

export interface SuggestionScore {
  parse_rate: number;
  completeness: number;
  required_fields_covered: number;
  confidence: number;
}

export interface SourceTestResponse {
  results: SourceTestResult[];
  results_truncated: boolean;
  score: SuggestionScore;
}

export interface WriteSourceResponse {
  name: string;
  written: boolean;
  path: string;
  backed_up: boolean;
}

export interface DisableSourceResponse {
  name: string;
  disabled: boolean;
  path: string;
}

export interface LoadError {
  path: string;
  error: string;
}

export interface ReloadStatus {
  last_reload_ns: number | null;
  reload_count: number;
  load_errors: LoadError[];
}

// ---------------------------------------------------------------------------
// suggest.py (POST /suggest/parser — draft a source definition from samples,
// used by the Sources editor's "Generate from samples" button)

export interface GenerateSourceRequest {
  source_id: string;
  sample_lines?: string[];
  template_id?: string;
  name?: string;
  vendor?: string;
  product?: string;
}

export interface GenerateSourceResponse {
  yaml: string;
  score: SuggestionScore & { warnings: string[] };
}

// ---------------------------------------------------------------------------
// templates.py

export interface TemplateOut {
  template_id: string;
  source_id: string;
  template: string;
  count: number;
  first_seen_ns: number;
  last_seen_ns: number;
  suggested_fields: string[];
}

export interface FieldGuess {
  position: number;
  mask_type: string;
  inferred_semantic: string;
  confidence: number;
  example_values: string[];
}

export interface TemplateDetail extends TemplateOut {
  sample_lines: string[];
  inferred_fields: FieldGuess[];
}

export interface TemplateSuggestResponse {
  yaml: string;
  score: SuggestionScore;
  warnings: string[];
}

export interface DriftEntry {
  template_id: string;
  source_id: string;
  template: string;
  window_seconds: number;
  baseline_rate_per_s: number;
  current_rate_per_s: number;
  observed_in_window: number;
  expected_in_window: number;
  z_score: number | null;
}

// ---------------------------------------------------------------------------
// integrity.py

export interface IntegrityStatus {
  ledger_entries: number;
  total_events_sealed: number;
  last_seal_ns: number | null;
  chain_verified: boolean;
  last_verification_ns: number;
}

export interface ChainVerifyReport {
  ledger_present: boolean;
  entries_total: number;
  checked: number;
  ok: boolean;
  broken_at: number | null;
  broken_reason: string | null;
  head_hex: string;
}

export interface EventVerifyFailure {
  event_uid: string;
  locator: string;
  hash_ok: boolean;
  proof_ok: boolean;
  signature_ok: boolean;
  reason: string;
}

export interface EventsVerifyReport {
  checked: number;
  passed: number;
  failed: number;
  ledger_present: boolean;
  failures: EventVerifyFailure[];
}

export interface LedgerEntryOut {
  seq: number;
  batch_root: string;
  prev_chained_root: string;
  chained_root: string;
  leaf_count: number;
  first_event_uid: string | null;
  last_event_uid: string | null;
  sealed_at_ns: number;
  signature: string;
}

export interface LedgerEntryRow extends LedgerEntryOut {
  signature_ok: boolean;
  /** signature_ok AND the chain-link recompute — the ledger table's per-row badge. */
  verified: boolean;
}

export interface EventProofOut {
  event_uid: string;
  found: boolean;
  ok: boolean;
  hash_ok: boolean;
  proof_ok: boolean;
  signature_ok: boolean;
  leaf_index: number | null;
  recorded_hash: string | null;
  recomputed_hash: string | null;
  merkle_proof: MerkleProofStep[];
  ledger_entry: LedgerEntryOut | null;
  reason: string | null;
}

// ---------------------------------------------------------------------------
// dlq.py

export interface DeadLetterOut {
  event_uid: string;
  raw_hash: string;
  reason: string;
  stage: string;
  ts_ns: number;
  detail: Record<string, unknown>;
  raw_preview: string;
  raw_truncated: boolean;
  resolved: boolean;
}

export interface DlqListResponse {
  items: DeadLetterOut[];
  total: number;
  page: number;
  page_size: number;
}

export interface DlqListParams {
  page?: number;
  page_size?: number;
  reason?: string;
  stage?: string;
  unresolved_only?: boolean;
}

export interface DlqStats {
  total: number;
  resolved: number;
  unresolved: number;
  by_reason: Record<string, number>;
  by_stage: Record<string, number>;
}

export interface ReplayRequest {
  reason?: string | null;
  since?: string | null;
  dry_run?: boolean;
}

export interface ReplayReport {
  reason: string | null;
  since: string | null;
  dry_run: boolean;
  candidates: number;
  succeeded: number;
  still_failing: number;
  written: number;
}

// ---------------------------------------------------------------------------
// ingest.py

export interface IngestResult {
  accepted: number;
  event_uids: string[];
}

export interface SampleRequest {
  lines: string[];
  source_id?: string | null;
}

export interface ReplayStartResponse {
  task_id: string;
}

export interface IngestReplayProgress {
  task_id: string;
  file: string;
  rate_eps: number;
  status: "running" | "completed" | "stopped" | "failed";
  lines_total: number;
  lines_sent: number;
  started_ns: number;
  finished_ns: number | null;
  error: string | null;
}

export interface ListenerStatus {
  name: string;
  protocol: string;
  port: number;
  events_received: number;
  bytes_received: number;
}
