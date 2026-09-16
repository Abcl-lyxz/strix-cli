import { isRecord, type WorkspaceRow } from "./contracts";

export const requestId = () => crypto.randomUUID();

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

export function sendCommand<T = WorkspaceRow>(
  name: string,
  payload: WorkspaceRow = {},
  id: string = requestId(),
): Promise<T> {
  return requestJson<T>("/api/app/commands", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ command: name, payload, request_id: id }),
  });
}
