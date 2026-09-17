import { isRecord } from "./contracts";

export async function requestJson<T>(path: string, options?: RequestInit): Promise<T> {
  const response = await fetch(path, { cache: "no-store", ...options });
  const value: unknown = await response.json();
  if (!response.ok) {
    const message = isRecord(value) && typeof value.error === "string"
      ? value.error
      : `Request failed (${response.status})`;
    throw new Error(message);
  }
  return value as T;
}
