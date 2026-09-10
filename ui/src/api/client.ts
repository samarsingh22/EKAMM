/**
 * Thin fetch wrapper every `src/api/*.ts` module builds on.
 *
 * Relative to `/api/v1` — proxied to the management API in dev (see
 * `vite.config.ts`) and served same-origin in production, so no base URL
 * ever needs configuring per environment.
 */

const API_BASE = "/api/v1";

export class ApiError extends Error {
  readonly status: number;
  readonly detail: unknown;

  constructor(status: number, detail: unknown) {
    super(typeof detail === "string" ? detail : `request failed with status ${status}`);
    this.name = "ApiError";
    this.status = status;
    this.detail = detail;
  }
}

/** Build a query string from a params object, dropping `undefined`/`null`/`""` entries. */
export function toQueryString<T extends object>(params: T): string {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params as Record<string, unknown>)) {
    if (value === undefined || value === null || value === "") continue;
    search.set(key, String(value));
  }
  const qs = search.toString();
  return qs ? `?${qs}` : "";
}

type JsonBody = object;

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    headers: init?.body ? { "Content-Type": "application/json" } : undefined,
    ...init,
  });

  if (!response.ok) {
    let detail: unknown;
    try {
      const body = await response.json();
      detail = body?.detail ?? body;
    } catch {
      detail = await response.text().catch(() => undefined);
    }
    throw new ApiError(response.status, detail);
  }

  if (response.status === 204) {
    return undefined as T;
  }
  return (await response.json()) as T;
}

export const api = {
  get: <T>(path: string): Promise<T> => request<T>(path),

  post: <T>(path: string, body?: JsonBody): Promise<T> =>
    request<T>(path, { method: "POST", body: body !== undefined ? JSON.stringify(body) : undefined }),

  /** For POST endpoints whose body is raw text (YAML), not JSON — sources.py's validate/PUT. */
  postText: <T>(path: string, text: string): Promise<T> =>
    request<T>(path, { method: "POST", headers: { "Content-Type": "text/plain" }, body: text }),

  putText: <T>(path: string, text: string): Promise<T> =>
    request<T>(path, { method: "PUT", headers: { "Content-Type": "text/plain" }, body: text }),

  delete: <T>(path: string): Promise<T> => request<T>(path, { method: "DELETE" }),
};
