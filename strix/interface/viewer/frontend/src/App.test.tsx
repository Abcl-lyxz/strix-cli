import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, expect, test, vi } from "vitest";
import App, { mergeEvents } from "./App";

vi.mock("@/components/live/AgentGraph", () => ({
  default: () => <div>Agent graph</div>,
}));

class Stream {
  static current: Stream;
  onopen: (() => void) | null = null;
  onerror: (() => void) | null = null;
  onmessage: ((event: { data: string }) => void) | null = null;

  constructor() {
    Stream.current = this;
  }

  close() {}

  emit(value: unknown) {
    this.onmessage?.({ data: JSON.stringify(value) });
  }
}

const requests: Array<{ path: string; method: string }> = [];

beforeEach(() => {
  requests.length = 0;
  vi.stubGlobal("EventSource", Stream);
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: string | URL | Request, options?: RequestInit) => {
      const path = String(input);
      requests.push({ path, method: options?.method ?? "GET" });
      const value = path.startsWith("/api/artifacts")
        ? { artifacts: [{ path: "evidence/request.txt", size: 1024 }] }
        : path === "/api/runs"
          ? { runs: [{ name: "saved-run", status: "completed" }] }
          : path === "/api/capabilities"
            ? { read_only: true }
            : {};
      return { ok: true, json: async () => value };
    }),
  );
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

function mount() {
  render(<App />);
  act(() => {
    Stream.current.onopen?.();
    Stream.current.emit({
      state: { scan_state: "running", run_name: "live-run" },
      reset: true,
      events: [],
      agents: [],
      findings: [],
      attachments: [],
    });
  });
}

test("viewer exposes observation only and never renders mutation controls", () => {
  mount();
  expect(screen.getByText("Read-only. Use the terminal TUI to control Strix.")).toBeTruthy();
  expect(screen.queryByRole("textbox", { name: "Prompt" })).toBeNull();
  expect(screen.queryByRole("button", { name: /^Send/ })).toBeNull();
  expect(screen.queryByRole("button", { name: /Connect provider/ })).toBeNull();
  expect(screen.queryByRole("button", { name: /Notifications/ })).toBeNull();
  expect(requests.every((request) => request.method === "GET")).toBe(true);
});

test("reconnect snapshot replaces old events and malformed events keep the viewer mounted", () => {
  mount();
  act(() =>
    Stream.current.emit({
      reset: true,
      events: [{ id: "old", data: { content: "old content" } }],
    }),
  );
  expect(screen.getByText("old content")).toBeTruthy();

  act(() =>
    Stream.current.emit({
      reset: true,
      events: [{ id: "new", data: { content: "new content" } }],
    }),
  );
  expect(screen.queryByText("old content")).toBeNull();
  act(() => Stream.current.onmessage?.({ data: "not json" }));
  expect(screen.getByRole("navigation", { name: "Read-only viewer navigation" })).toBeTruthy();
  expect(screen.getByRole("alert").textContent).toContain("Invalid workspace update");
});

test("artifact and report navigation remains available through GET downloads", async () => {
  mount();
  fireEvent.click(screen.getByRole("button", { name: "Artifacts & reports" }));
  expect(await screen.findByText("evidence/request.txt")).toBeTruthy();
  expect(screen.getByRole("link", { name: "Download PDF report" }).getAttribute("href")).toBe(
    "/api/report/pdf",
  );
  await waitFor(() =>
    expect(requests.some((request) => request.path === "/api/artifacts")).toBe(true),
  );
  expect(requests.every((request) => request.method === "GET")).toBe(true);
});

test("run history remains browsable without mutation requests", async () => {
  mount();
  fireEvent.click(screen.getByRole("button", { name: "Run history" }));
  expect(await screen.findByRole("button", { name: /saved-run/ })).toBeTruthy();
  expect(requests.every((request) => request.method === "GET")).toBe(true);
});

test("merge bounds rendering, updates existing IDs, and deduplicates acknowledgements", () => {
  const events = Array.from({ length: 6000 }, (_, index) => ({
    id: String(index),
    content: "first",
  }));
  const merged = mergeEvents(events, [{ id: "5999", content: "updated" }]);
  expect(merged).toHaveLength(5000);
  expect(merged.at(-1)?.content).toBe("updated");
});
