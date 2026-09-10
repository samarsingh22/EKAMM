import { api } from "./client";
import type { GenerateSourceRequest, GenerateSourceResponse } from "./types";

/** `/api/v1/suggest` — see `ulpf/api/suggest.py`. */
export const suggestApi = {
  parser: (payload: GenerateSourceRequest): Promise<GenerateSourceResponse> =>
    api.post("/suggest/parser", payload),
};
