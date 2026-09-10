/** Safe nested-property read on an arbitrary JSON-shaped object (an OCSF record). */
export function getPath(obj: unknown, path: string[]): unknown {
  let node = obj;
  for (const key of path) {
    if (node === null || typeof node !== "object") return undefined;
    node = (node as Record<string, unknown>)[key];
  }
  return node;
}

export function getString(obj: unknown, path: string[]): string | undefined {
  const value = getPath(obj, path);
  return typeof value === "string" ? value : undefined;
}

export function getNumber(obj: unknown, path: string[]): number | undefined {
  const value = getPath(obj, path);
  return typeof value === "number" ? value : undefined;
}
