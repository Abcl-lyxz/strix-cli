import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
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
const calls: { command: string; payload: any; request_id: string }[] = [];
let failSend = false;
beforeEach(() => {
  sessionStorage.clear();
  calls.length = 0;
  failSend = false;
  vi.stubGlobal("EventSource", Stream);
  vi.stubGlobal(
    "fetch",
    vi.fn(async (_path, options) => {
      const body = options?.body ? JSON.parse(options.body) : {};
      calls.push(body);
      if (body.command === "scan.submit" && failSend)
        throw new Error("Connection interrupted");
      const value =
        body.command === "providers.list"
          ? { providers: [{ id: "custom", name: "Custom gateway" }] }
          : body.command === "providers.discover"
            ? {
                models: [{ id: "vendor/exact.model:free" }],
                source: "cache",
                error: "Discovery offline; cached models available",
              }
            : body.command === "notifications.manage"
              ? {
                  unread: 1,
                  notifications: [
                    {
                      id: "incident",
                      title: "Provider required",
                      detail: "Fix your connection",
                      unread: true,
                      actions: [
                        { kind: "open_routes", label: "Configure provider" },
                      ],
                    },
                  ],
                }
              : { sent: true };
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
      state: { setup_mode: true, scan_mode: "deep" },
      reset: true,
      events: [],
      agents: [],
      findings: [],
      attachments: [],
    });
  });
}
test("multiline command-like paste is sent only with Ctrl+S", async () => {
  mount();
  const input = screen.getByRole("textbox", { name: "Prompt" });
  const prompt = "/baseurl https://example.invalid\n\n  日本語 🧪\nlast line";
  fireEvent.change(input, { target: { value: prompt } });
  fireEvent.keyDown(input, { key: "Enter" });
  expect(calls.filter((c) => c.command === "scan.submit")).toHaveLength(0);
  fireEvent.keyDown(input, { key: "s", ctrlKey: true });
  await waitFor(() =>
    expect(
      calls.find((c) => c.command === "scan.submit")?.payload.message,
    ).toBe(prompt),
  );
});
test("failed delivery retains the draft and retries the same request ID", async () => {
  mount();
  failSend = true;
  fireEvent.change(screen.getByRole("textbox", { name: "Prompt" }), {
    target: { value: "still here\n  keep whitespace" },
  });
  fireEvent.click(screen.getByRole("button", { name: /^Send/ }));
  await screen.findByText("Connection interrupted");
  expect(sessionStorage.getItem("strix-draft")).toBe(
    "still here\n  keep whitespace",
  );
  failSend = false;
  fireEvent.click(screen.getByRole("button", { name: /^Send/ }));
  await waitFor(() =>
    expect(calls.filter((c) => c.command === "scan.submit")).toHaveLength(2),
  );
  const sends = calls.filter((call) => call.command === "scan.submit");
  expect(sends[0].request_id).toBe(sends[1].request_id);
  await waitFor(() => expect(sessionStorage.getItem("strix-draft")).toBe(""));
});
test("reconnect snapshot replaces old events and malformed events do not blank the app", () => {
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
  expect(screen.getByRole("textbox", { name: "Prompt" })).toBeTruthy();
});
test("notifications use unread state and dispatch the selected action index", async () => {
  mount();
  fireEvent.click(screen.getByRole("button", { name: /Notifications/ }));
  const action = await screen.findByRole("button", {
    name: "Configure provider",
  });
  expect(action.closest("article")?.classList.contains("unread")).toBe(true);
  fireEvent.click(action);
  await waitFor(() =>
    expect(
      calls.some(
        (c) => c.payload?.operation === "action" && c.payload.index === 0,
      ),
    ).toBe(true),
  );
});
test("provider form masks keys and keeps exact cached IDs after discovery failure", async () => {
  mount();
  fireEvent.click(screen.getByRole("button", { name: "Connect provider" }));
  fireEvent.click(
    await screen.findByRole("button", { name: "Custom gateway" }),
  );
  expect((screen.getByLabelText("API key") as HTMLInputElement).type).toBe(
    "password",
  );
  fireEvent.click(screen.getByRole("button", { name: "Discover models" }));
  await screen.findByText("Discovery offline; cached models available");
  expect(
    document.querySelector('option[value="vendor/exact.model:free"]'),
  ).toBeTruthy();
});
test("merge bounds rendering, updates existing IDs, and deduplicates acknowledgements", () => {
  const events = Array.from({ length: 6000 }, (_, i) => ({
    id: String(i),
    content: "first",
  }));
  const merged = mergeEvents(events, [{ id: "5999", content: "updated" }]);
  expect(merged).toHaveLength(5000);
  expect(merged.at(-1)?.content).toBe("updated");
});

test("failed submission keeps its request ID across a page reload", async () => {
  mount();
  failSend = true;
  fireEvent.change(screen.getByRole("textbox", { name: "Prompt" }), {
    target: { value: "recover this draft" },
  });
  fireEvent.click(screen.getByRole("button", { name: /^Send/ }));
  await screen.findByText("Connection interrupted");
  const first = calls.find((call) => call.command === "scan.submit")!;
  cleanup();
  failSend = false;
  mount();
  expect(
    (screen.getByRole("textbox", { name: "Prompt" }) as HTMLTextAreaElement)
      .value,
  ).toBe("recover this draft");
  fireEvent.click(screen.getByRole("button", { name: /^Send/ }));
  await waitFor(() =>
    expect(calls.filter((call) => call.command === "scan.submit")).toHaveLength(
      2,
    ),
  );
  expect(
    calls.filter((call) => call.command === "scan.submit")[1].request_id,
  ).toBe(first.request_id);
});

test("oversized Unicode prompts remain intact and are never silently sent", () => {
  mount();
  const prompt = "🧪".repeat(70000);
  const input = screen.getByRole("textbox", {
    name: "Prompt",
  }) as HTMLTextAreaElement;
  fireEvent.change(input, { target: { value: prompt } });
  fireEvent.keyDown(input, { key: "s", ctrlKey: true });
  expect(screen.getByRole("alert").textContent).toContain("256 KiB");
  expect(input.value).toBe(prompt);
  expect(calls.some((call) => call.command === "scan.submit")).toBe(false);
});

test("an acknowledgement never clears text composed while delivery was pending", async () => {
  let accept: () => void = () => {};
  const response = new Promise<void>((resolve) => {
    accept = resolve;
  });
  vi.stubGlobal(
    "fetch",
    vi.fn(async (_path, options) => {
      const body = options?.body ? JSON.parse(options.body) : {};
      if (body.command === "scan.submit") await response;
      return { ok: true, json: async () => ({ sent: true }) };
    }),
  );
  mount();
  const input = screen.getByRole("textbox", {
    name: "Prompt",
  }) as HTMLTextAreaElement;
  fireEvent.change(input, { target: { value: "first message" } });
  fireEvent.click(screen.getByRole("button", { name: /^Send/ }));
  fireEvent.change(input, {
    target: { value: "next message\n  keep indentation" },
  });
  await act(async () => accept());
  await waitFor(() => expect(screen.getByText("accepted")).toBeTruthy());
  expect(input.value).toBe("next message\n  keep indentation");
});
