import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  Activity,
  ArrowUp,
  Bell,
  FolderOpen,
  History,
  Paperclip,
  Plus,
  Search,
  Settings,
  Sliders,
  Square,
  X,
} from "lucide-react";
import AgentGraph from "@/components/live/AgentGraph";
import {
  AgentTranscript,
  buildGraphAgents,
} from "@/components/live/AgentTranscript";
import Markdown from "@/components/live/tool-renderers/Markdown";
import "./workspace.css";

type Row = Record<string, any>;
type Dialog = {
  title: string;
  command?: string;
  payload?: Row;
  fields?: Row[];
  rows?: Row[];
  kind?: string;
  error?: string;
};
const uid = () => crypto.randomUUID();
const label = (row: Row) =>
  String(row.label || row.title || row.name || row.id || row.path || "Item");
const text = (value: any) =>
  typeof value === "string" ? value : JSON.stringify(value, null, 2);
async function api(path: string, options?: RequestInit) {
  const response = await fetch(path, { cache: "no-store", ...options });
  const value = await response.json();
  if (!response.ok)
    throw new Error(value.error || `Request failed (${response.status})`);
  return value;
}
export async function command(
  name: string,
  payload: Row = {},
  requestId: string = uid(),
) {
  return api("/api/app/commands", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ command: name, payload, request_id: requestId }),
  });
}
export function mergeEvents(previous: Row[], incoming: Row[], reset = false) {
  const map = new Map((reset ? [] : previous).map((item) => [item.id, item]));
  incoming.forEach((item) => map.set(item.id, item));
  return [...map.values()].slice(-5000);
}
export default function App() {
  const [state, setState] = useState<Row>({ setup_mode: true });
  const [events, setEvents] = useState<Row[]>([]),
    [agents, setAgents] = useState<Row[]>([]),
    [findings, setFindings] = useState<Row[]>([]);
  const [attachments, setAttachments] = useState<Row[]>([]),
    [runs, setRuns] = useState<Row[]>([]),
    [artifacts, setArtifacts] = useState<Row[]>([]);
  const [view, setView] = useState("workspace"),
    [search, setSearch] = useState(""),
    [error, setError] = useState("");
  const [selectedAgent, setSelectedAgent] = useState<string | null>(null);
  const [showGraph, setShowGraph] = useState(false);
  const [expanded, setExpanded] = useState(false),
    [streamEpoch, setStreamEpoch] = useState(0);
  const [inboxFilter, setInboxFilter] = useState("all");
  const [online, setOnline] = useState(false),
    [dialog, setDialog] = useState<Dialog | null>(null),
    [filter, setFilter] = useState("");
  const [draft, setDraft] = useState(
    () => sessionStorage.getItem("strix-draft") || "",
  );
  const [delivery, setDelivery] = useState(""),
    [historical, setHistorical] = useState<Row | null>(null);
  const pending = useRef<{ id: string; message: string } | null>(
      (() => {
        try {
          return JSON.parse(sessionStorage.getItem("strix-pending") || "null");
        } catch {
          return null;
        }
      })(),
    ),
    editor = useRef<HTMLTextAreaElement>(null);
  const completionTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const runQuery = historical
    ? `?run=${encodeURIComponent(historical.name)}`
    : "";
  const perform = useCallback(async (name: string, payload: Row = {}) => {
    try {
      setError("");
      return await command(name, payload);
    } catch (e) {
      setError((e as Error).message);
      throw e;
    }
  }, []);
  const openList = async (
    title: string,
    name: string,
    key: string,
    kind: string,
    payload: Row = {},
  ) => {
    setFilter("");
    setDialog({ title, rows: [], kind });
    try {
      const data = await perform(name, payload);
      setDialog({ title, rows: data[key] || [], kind });
    } catch (e) {
      setDialog((d) => d && { ...d, error: (e as Error).message });
    }
  };
  const openProviders = () =>
    openList("Connect a provider", "providers.list", "providers", "providers");
  const openSettings = () =>
    openList("Settings", "settings.list", "fields", "settings");
  const openInbox = () =>
    openList(
      "Notifications",
      "notifications.manage",
      "notifications",
      "notifications",
      { operation: "list" },
    );
  const attach = (path = "") =>
    setDialog({
      title: "Attach a file or folder",
      command: "attachments.add",
      fields: [
        { id: "path", label: "Path on this computer", value: path },
        {
          id: "role",
          label: "Use as",
          value: "context",
          options: ["context", "target"],
        },
      ],
    });
  const completePath = (value: string) => {
    if (completionTimer.current) clearTimeout(completionTimer.current);
    completionTimer.current = setTimeout(() => {
      void command("paths.complete", { query: value })
        .then((data) =>
          setDialog((current) =>
            current?.command === "attachments.add"
              ? {
                  ...current,
                  fields: current.fields?.map((field) =>
                    field.id === "path"
                      ? {
                          ...field,
                          suggestions: data.paths.map((item: Row) => item.path),
                        }
                      : field,
                  ),
                }
              : current,
          ),
        )
        .catch(() => {});
    }, 180);
  };
  const scanOptions = () =>
    setDialog({
      title: "Scan options",
      command: "setup.configure",
      fields: [
        {
          id: "scan_mode",
          label: "Scan mode",
          value: state.scan_mode,
          options: ["quick", "standard", "deep"],
        },
        {
          id: "max_budget_usd",
          label: "Budget (USD, blank for unlimited)",
          value: state.max_budget_usd,
          type: "number",
        },
        {
          id: "max_turns",
          label: "Maximum turns",
          value: state.max_turns,
          type: "number",
        },
        {
          id: "max_agents",
          label: "Maximum agents",
          value: state.max_agents,
          type: "number",
        },
        {
          id: "scope_mode",
          label: "Scope",
          value: state.scope_mode,
          options: ["auto", "full", "diff"],
        },
        { id: "diff_base", label: "Diff base", value: state.diff_base },
      ],
    });
  useEffect(() => {
    const url = new URL(location.href);
    url.searchParams.delete("token");
    history.replaceState(null, "", url);
    const stream = new EventSource("/api/app/events");
    stream.onopen = () => setOnline(true);
    stream.onerror = () => setOnline(false);
    stream.onmessage = (event) => {
      let data: Row;
      try {
        data = JSON.parse(event.data);
      } catch {
        setError(
          "Invalid workspace update; reconnecting for a fresh snapshot.",
        );
        stream.close();
        setOnline(false);
        setStreamEpoch((epoch) => epoch + 1);
        return;
      }
      if (data.state) setState(data.state);
      if (data.events)
        setEvents((old) => mergeEvents(old, data.events, data.reset));
      if (data.agents) setAgents(data.agents);
      if (data.findings) setFindings(data.findings);
      if (data.attachments) setAttachments(data.attachments);
    };
    return () => stream.close();
  }, [streamEpoch]);
  useEffect(() => {
    api("/api/capabilities")
      .then((data) => {
        if (data.initial_run) void browse({ name: data.initial_run });
      })
      .catch(() => {});
    return () => {
      if (completionTimer.current) clearTimeout(completionTimer.current);
    };
  }, []);
  useEffect(() => {
    sessionStorage.setItem("strix-draft", draft);
  }, [draft]);
  useEffect(() => {
    if (dialog)
      document
        .querySelector<HTMLInputElement>("dialog input, dialog select")
        ?.focus();
  }, [dialog?.title]);
  useEffect(() => {
    if (view === "history")
      api("/api/runs")
        .then((data) => setRuns(data.runs))
        .catch((e) => setError(e.message));
  }, [view, state.scan_state]);
  useEffect(() => {
    if (view === "evidence")
      api("/api/artifacts" + runQuery)
        .then((data) => setArtifacts(data.artifacts))
        .catch((e) => setError(e.message));
  }, [view, runQuery, state.scan_state]);
  const send = async () => {
    if (!draft.trim() || delivery === "pending") return;
    if (new TextEncoder().encode(draft).length > 262144) {
      setError("Prompt exceeds 256 KiB. Attach a file or shorten the prompt.");
      return;
    }
    if (!pending.current || pending.current.message !== draft)
      pending.current = { id: uid(), message: draft };
    sessionStorage.setItem("strix-pending", JSON.stringify(pending.current));
    setDelivery("pending");
    setError("");
    try {
      await command("scan.submit", { message: draft }, pending.current.id);
      setDraft((current) => (current === draft ? "" : current));
      pending.current = null;
      sessionStorage.removeItem("strix-pending");
      setDelivery("accepted");
      editor.current?.focus();
    } catch (e) {
      setError((e as Error).message);
      setDelivery("failed");
    }
  };
  const browse = async (run: Row) => {
    try {
      const query = `?run=${encodeURIComponent(run.name)}`;
      const [transcript, reports] = await Promise.all([
        api("/api/transcript" + query),
        api("/api/vulnerabilities" + query),
      ]);
      setHistorical({ ...run, ...transcript, findings: reports });
      setView("workspace");
    } catch (e) {
      setError((e as Error).message);
    }
  };
  const choose = (row: Row) => {
    if (dialog?.kind === "routing") {
      setDialog({
        title: `Advanced routing · ${row.name}`,
        command: "providers.advanced",
        payload: { name: row.name },
        fields: [
          {
            id: "priority",
            label: "Priority",
            type: "number",
            value: row.priority,
          },
          {
            id: "max_concurrency",
            label: "Concurrent requests",
            type: "number",
            value: row.max_concurrency,
          },
          {
            id: "rpm",
            label: "Requests per minute (blank for unlimited)",
            type: "number",
            value: row.rpm,
          },
          {
            id: "tpm",
            label: "Tokens per minute (blank for unlimited)",
            type: "number",
            value: row.tpm,
          },
          {
            id: "enabled",
            label: "Enabled",
            type: "checkbox",
            value: row.enabled,
          },
          {
            id: "persist",
            label: "Save as default",
            type: "checkbox",
            value: false,
          },
        ],
      });
    }
    if (dialog?.kind === "profiles") {
      void perform("routes.manage", { operation: "select", name: row.name })
        .then(() => setDialog(null))
        .catch(() => {});
    }
    if (dialog?.kind === "providers")
      setDialog({
        title: row.name,
        command: "providers.connect",
        payload: { provider_id: row.id },
        fields: [
          { id: "name", label: "Connection name", value: row.id },
          { id: "base_url", label: "Endpoint", value: row.base_url },
          { id: "api_key", label: "API key", type: "password" },
          { id: "model_id", label: "Model ID", value: "" },
          {
            id: "persist",
            label: "Save as default",
            type: "checkbox",
            value: false,
          },
        ],
      });
    if (dialog?.kind === "settings")
      setDialog({
        title: row.label,
        command: "settings.update",
        payload: { id: row.id },
        fields: [
          {
            id: "value",
            label: `${row.label} · ${row.source} · ${row.apply}`,
            value: row.value,
            type:
              row.type === "secret"
                ? "password"
                : row.type === "boolean"
                  ? "checkbox"
                  : row.type === "number"
                    ? "number"
                    : "text",
          },
          {
            id: "persist",
            label: "Save as default",
            type: "checkbox",
            value: false,
          },
        ],
      });
    if (dialog?.kind === "commands") {
      setDialog(null);
      row.run();
    }
  };
  const submitForm = async (form: HTMLFormElement, discover = false) => {
    const values = new FormData(form),
      payload: Row = { ...dialog?.payload };
    dialog?.fields?.forEach((field) => {
      const value = values.get(field.id);
      payload[field.id] =
        field.type === "checkbox"
          ? value === "on"
          : field.type === "number"
            ? value === ""
              ? null
              : Number(value)
            : value;
    });
    try {
      if (discover) {
        const data = await perform("providers.discover", payload);
        setDialog(
          (d) =>
            d && {
              ...d,
              fields: d.fields?.map((field) => ({
                ...field,
                value: payload[field.id],
                ...(field.id === "model_id"
                  ? { suggestions: data.models?.map((m: Row) => m.id) }
                  : {}),
              })),
              error:
                data.error ||
                `Models from ${data.source}. You can also enter a model ID.`,
            },
        );
      } else {
        await perform(dialog!.command!, payload);
        setDialog(null);
      }
    } catch (e) {
      setDialog((d) => d && { ...d, error: (e as Error).message });
    }
  };
  const displayedAgents = historical?.agents || agents;
  const displayedEvents = historical?.events || events;
  const graph = useMemo(
    () => buildGraphAgents(displayedAgents, displayedEvents),
    [displayedAgents, displayedEvents],
  );
  const upload = async (files: FileList | null) => {
    if (!files) return;
    for (const file of Array.from(files)) {
      try {
        setDelivery("uploading");
        await api("/api/attachments/upload", {
          method: "POST",
          headers: {
            "Content-Type": "application/octet-stream",
            "X-File-Name": encodeURIComponent(file.name),
          },
          body: file,
        });
        setDelivery("attached");
      } catch (e) {
        setError((e as Error).message);
        setDelivery("upload failed");
        break;
      }
    }
  };
  const displayedFindings = historical?.findings || findings;
  const visibleEvents = displayedEvents
    .filter(
      (event: Row) =>
        (!selectedAgent || event.agent_id === selectedAgent) &&
        text(event).toLowerCase().includes(search.toLowerCase()),
    )
    .slice(-300);
  const palette = () => {
    setFilter("");
    setDialog({
      title: "Commands",
      kind: "commands",
      rows: [
        { label: "Connect provider", run: openProviders },
        {
          label: "Advanced routing",
          run: () =>
            openList(
              "Advanced routing",
              "providers.list",
              "profiles",
              "routing",
            ),
        },
        {
          label: "Choose saved model connection",
          run: () =>
            openList(
              "Model connections",
              "providers.list",
              "profiles",
              "profiles",
            ),
        },
        {
          label: "Test model and tool support",
          run: () =>
            perform("providers.test")
              .then(() => setDelivery("Model and tool support verified"))
              .catch(() => {}),
        },
        { label: "Settings", run: openSettings },
        {
          label: "Configure MCP",
          run: () =>
            setDialog({
              title: "MCP connection · next scan",
              command: "mcp.update",
              fields: [
                { id: "name", label: "Name" },
                {
                  id: "transport",
                  label: "Transport",
                  value: "http",
                  options: ["http", "stdio"],
                },
                { id: "url", label: "HTTP endpoint" },
                { id: "command", label: "Executable (stdio)" },
                { id: "args", label: "Arguments (JSON array)", value: "[]" },
                { id: "token", label: "Bearer token", type: "password" },
                {
                  id: "persist",
                  label: "Save as default",
                  type: "checkbox",
                  value: false,
                },
              ],
            }),
        },
        {
          label: "Notification preferences",
          run: () =>
            setDialog({
              title: "Notification preferences",
              command: "notifications.preferences",
              fields: [
                {
                  id: "category",
                  label: "Category",
                  value: "runtime",
                  options: ["runtime", "security", "model", "scan", "storage"],
                },
                {
                  id: "minimum_severity",
                  label: "Minimum severity",
                  value: "warning",
                  options: ["info", "warning", "error", "critical"],
                },
                {
                  id: "immediate",
                  label: "Show immediate alerts",
                  type: "checkbox",
                  value: true,
                },
              ],
            }),
        },
        { label: "Scan options", run: scanOptions },
        { label: "Attach file or folder", run: () => attach() },
        { label: "Notifications", run: openInbox },
        { label: "History", run: () => setView("history") },
      ],
    });
  };
  return (
    <div
      className="workspace-shell"
      onKeyDown={(e) => {
        if ((e.ctrlKey || e.metaKey) && e.key === "k") {
          e.preventDefault();
          palette();
        }
        if (e.key === "Escape") setDialog(null);
      }}
    >
      <aside className="workspace-nav">
        <div className="brand">
          <Activity size={24} />
          <strong>strix</strong>
          <span>LOCAL</span>
        </div>
        <button
          className="new-scan"
          onClick={() =>
            perform("scan.new")
              .then(() => {
                setHistorical(null);
                setView("workspace");
              })
              .catch(() => {})
          }
        >
          <Plus size={17} />
          New scan
        </button>
        {[
          ["workspace", "Workspace", Activity],
          ["findings", "Findings", FolderOpen],
          ["evidence", "Evidence & reports", Paperclip],
          ["history", "History", History],
        ].map(([id, title, Icon]: any) => (
          <button
            key={id}
            aria-current={view === id ? "page" : undefined}
            onClick={() => setView(id)}
          >
            <Icon size={17} />
            {title}
          </button>
        ))}
        <div className="nav-bottom">
          <button onClick={openInbox}>
            <Bell size={17} />
            Notifications{" "}
            <span className="count">{state.notification_unread || 0}</span>
          </button>
          <button onClick={openSettings}>
            <Settings size={17} />
            Settings
          </button>
          <button onClick={palette}>
            <Search size={17} />
            Commands <kbd>Ctrl K</kbd>
          </button>
        </div>
      </aside>
      <main className="workspace-main">
        <header>
          <div>
            <span className={online ? "status-dot online" : "status-dot"} />
            {online ? state.scan_state || "Ready" : "Reconnecting…"}
            <span className="muted">
              {" "}
              / {historical?.name || state.run_name || "New workspace"}
            </span>
          </div>
          <button onClick={openProviders}>
            {state.selected_route || state.model || "Connect provider"}
          </button>
        </header>
        {error && (
          <div role="alert" className="error-banner">
            {error}
            <button aria-label="Dismiss error" onClick={() => setError("")}>
              <X size={16} />
            </button>
          </div>
        )}
        {historical && (
          <div className="notice">
            Viewing saved run <strong>{historical.name}</strong>
            <button
              onClick={() =>
                perform("scan.resume", { run: historical.name })
                  .then(() => {
                    setHistorical(null);
                    setDraft("Continue this scan.");
                  })
                  .catch(() => {})
              }
            >
              Resume
            </button>
            <button onClick={() => setHistorical(null)}>
              Return to active workspace
            </button>
          </div>
        )}
        {view === "workspace" && (
          <>
            <section className="workspace-feed">
              {state.recovery?.title && (
                <div className="notice" role="status">
                  <strong>{state.recovery.title}</strong>
                  <p>{state.recovery.detail}</p>
                  <button onClick={openProviders}>
                    Change provider or model
                  </button>
                  <button
                    onClick={() =>
                      perform("scan.retry", {
                        agent_id: state.recovery.agent_id,
                      }).catch(() => {})
                    }
                  >
                    Retry
                  </button>
                  <button onClick={() => perform("scan.stop").catch(() => {})}>
                    Stop
                  </button>
                </div>
              )}
              {state.setup_mode && !historical && (
                <div className="welcome">
                  <Activity size={38} />
                  <h1>What would you like to test?</h1>
                  <p>
                    Describe the task, choose the scope, and attach the files
                    you need.
                  </p>
                  <div className="readiness">
                    <span>
                      {state.api_key_configured
                        ? "Credential configured"
                        : "Provider setup needed"}
                    </span>
                    <span>{state.scan_mode || "deep"} scan</span>
                    <span>{state.target_count || 0} targets</span>
                  </div>
                  {state.recent_runs?.length > 0 && (
                    <div className="recent-home">
                      <p>Recent sessions</p>
                      {state.recent_runs.slice(0, 3).map((run: Row) => (
                        <button key={run.name} onClick={() => browse(run)}>
                          {run.name}
                        </button>
                      ))}
                    </div>
                  )}
                </div>
              )}
              {displayedAgents.length > 0 && (
                <>
                  <div className="agent-strip">
                    <button onClick={() => setShowGraph(!showGraph)}>
                      {showGraph ? "Hide graph" : "Agent graph"}
                    </button>
                    <button onClick={() => setSelectedAgent(null)}>
                      All agents
                    </button>
                    {displayedAgents.map((agent: Row) => (
                      <button
                        key={agent.id}
                        onClick={() => setSelectedAgent(agent.id)}
                        aria-pressed={selectedAgent === agent.id}
                      >
                        {agent.name}{" "}
                        <small>
                          {agent.wait_kind === "provider"
                            ? "provider required"
                            : agent.status}
                        </small>
                      </button>
                    ))}
                  </div>
                  {showGraph && (
                    <div style={{ height: 360 }}>
                      <AgentGraph
                        agents={graph}
                        selectedAgentId={selectedAgent}
                        onSelectAgent={setSelectedAgent}
                        eventsLoaded
                        eventsEmpty={!displayedEvents.length}
                      />
                    </div>
                  )}
                </>
              )}
              {displayedEvents.length > 0 && (
                <label className="search">
                  <Search size={16} />
                  <input
                    aria-label="Search transcript"
                    value={search}
                    onChange={(e) => setSearch(e.target.value)}
                    placeholder="Search transcript and tool output"
                  />
                </label>
              )}
              {visibleEvents.map((event: Row, index: number) => {
                const data = event.data || event;
                if (event.type === "tool")
                  return (
                    <AgentTranscript
                      key={event.id || index}
                      agent={
                        displayedAgents.find(
                          (a: Row) => a.id === event.agent_id,
                        ) || {
                          id: event.agent_id,
                          name: event.agent_id,
                          status: "running",
                        }
                      }
                      events={[event as any]}
                      showHeader={false}
                    />
                  );
                return (
                  <article className="event" key={event.id || index}>
                    <div className="event-label">
                      {data.role ||
                        data.tool_name ||
                        data.name ||
                        event.type ||
                        "Event"}
                      <small>{event.agent_id}</small>
                    </div>
                    {data.content || data.text || data.message ? (
                      <Markdown
                        text={text(data.content || data.text || data.message)}
                      />
                    ) : (
                      <details>
                        <summary>{data.status || "Details"}</summary>
                        <pre>{text(data)}</pre>
                      </details>
                    )}
                  </article>
                );
              })}
              {!historical &&
                state.messages?.map((message: Row) => (
                  <div className={`notice ${message.level}`} key={message.id}>
                    {message.text}
                  </div>
                ))}
            </section>
            {!historical && (
              <section
                className={
                  expanded ? "composer-panel expanded" : "composer-panel"
                }
              >
                <div className="chips">
                  {state.targets?.map((target: string, index: number) => (
                    <span key={target}>
                      Target · {target}
                      <button
                        aria-label={`Remove target ${target}`}
                        onClick={() =>
                          perform("setup.remove_target", {
                            target,
                            target_id: state.target_ids?.[index],
                          }).catch(() => {})
                        }
                      >
                        ×
                      </button>
                    </span>
                  ))}
                  {attachments.map((item) => (
                    <span key={item.id} title={item.workspace_path}>
                      {item.role} · {item.name}
                      <button
                        aria-label={`Remove ${item.name}`}
                        onClick={() =>
                          perform("attachments.remove", { id: item.id }).catch(
                            () => {},
                          )
                        }
                      >
                        ×
                      </button>
                    </span>
                  ))}
                </div>
                <textarea
                  ref={editor}
                  aria-label="Prompt"
                  placeholder="Describe your task. Enter adds a new line."
                  value={draft}
                  onChange={(e) => setDraft(e.target.value)}
                  onKeyDown={(e) => {
                    if (
                      (e.ctrlKey || e.metaKey) &&
                      e.key.toLowerCase() === "e"
                    ) {
                      e.preventDefault();
                      setExpanded((value) => !value);
                    }
                    if (
                      (e.ctrlKey || e.metaKey) &&
                      e.key.toLowerCase() === "s"
                    ) {
                      e.preventDefault();
                      void send();
                    }
                    if (e.key === "Tab") {
                      const before = draft.slice(
                        0,
                        e.currentTarget.selectionStart,
                      );
                      const match = before.match(
                        /(?:^|\s)@("[^"]*"?|'[^']*'?|[^\s]*)$/,
                      );
                      if (match) {
                        e.preventDefault();
                        attach(match[1]);
                        completePath(match[1]);
                      }
                    }
                  }}
                />
                <button
                  className="expand-editor"
                  onClick={() => setExpanded((value) => !value)}
                >
                  {expanded ? "Collapse editor" : "Expand editor"} · Ctrl E
                </button>
                <div className="composer-actions">
                  <button onClick={() => attach()}>
                    <Paperclip size={16} />
                    Attach path
                  </button>
                  <label className="upload-button">
                    Upload files
                    <input
                      aria-label="Upload files"
                      type="file"
                      multiple
                      onChange={(e) => {
                        void upload(e.target.files);
                        e.target.value = "";
                      }}
                    />
                  </label>
                  <button
                    onClick={() =>
                      setDialog({
                        title: "Add scan target",
                        command: "setup.add_target",
                        fields: [
                          {
                            id: "target",
                            label: "URL, file, folder, domain, or IP",
                          },
                        ],
                      })
                    }
                  >
                    Add target
                  </button>
                  <button onClick={scanOptions}>
                    <Sliders size={16} />
                    {state.scan_mode || "deep"}
                  </button>
                  <span className="delivery" role="status">
                    {delivery}
                  </span>
                  {state.scan_started &&
                    !["completed", "stopped", "failed"].includes(
                      state.scan_state,
                    ) && (
                      <button
                        onClick={() => perform("scan.stop").catch(() => {})}
                      >
                        <Square size={14} />
                        Stop
                      </button>
                    )}
                  <button
                    className="send"
                    disabled={
                      !draft.trim() || delivery === "pending" || !online
                    }
                    onClick={send}
                  >
                    <ArrowUp size={17} />
                    Send <kbd>Ctrl S</kbd>
                  </button>
                </div>
                <small>
                  Enter for a newline · Ctrl+S to send · @path + Tab to attach ·
                  Draft saved in this browser tab
                </small>
                {state.pending_mount && (
                  <div className="notice">
                    Mount {state.pending_mount} as supporting context?
                    <button
                      onClick={() =>
                        perform("setup.confirm_mount", {
                          approved: true,
                        }).catch(() => {})
                      }
                    >
                      Mount folder
                    </button>
                    <button
                      onClick={() =>
                        perform("setup.confirm_mount", {
                          approved: false,
                        }).catch(() => {})
                      }
                    >
                      Continue without it
                    </button>
                  </div>
                )}
              </section>
            )}
          </>
        )}
        {view === "history" && (
          <section className="page">
            <h1>Local history</h1>
            {runs.length === 0 && <p>No saved scans yet.</p>}
            {runs.map((run) => (
              <button
                className="run-row"
                key={run.name}
                onClick={() => browse(run)}
              >
                <div>
                  <strong>{run.name}</strong>
                  <p>{run.target}</p>
                </div>
                <span>{run.status}</span>
              </button>
            ))}
          </section>
        )}
        {view === "findings" && (
          <section className="page">
            <h1>
              Findings <span className="muted">{displayedFindings.length}</span>
            </h1>
            {!displayedFindings.length && <p>No findings recorded.</p>}
            {displayedFindings.map((finding: Row, i: number) => (
              <details className="finding" key={finding.id || i}>
                <summary>
                  <span className={`severity ${finding.severity}`}>
                    {finding.severity}
                  </span>
                  {finding.title || finding.name}
                </summary>
                <Markdown
                  text={Object.entries(finding)
                    .filter(
                      ([k, v]) =>
                        typeof v === "string" &&
                        !["id", "title", "severity"].includes(k),
                    )
                    .map(([k, v]) => `### ${k.replaceAll("_", " ")}\n${v}`)
                    .join("\n\n")}
                />
              </details>
            ))}
          </section>
        )}
        {view === "evidence" && (
          <section className="page">
            <h1>Evidence & reports</h1>
            <p>Download artifacts directly from this computer.</p>
            <a
              className="artifact"
              href={"/api/report/pdf" + runQuery}
              download
            >
              Download PDF report
            </a>
            {artifacts.map((item) => (
              <a
                className="artifact"
                key={item.path}
                href={`/api/artifact?path=${encodeURIComponent(item.path)}${historical ? `&run=${encodeURIComponent(historical.name)}` : ""}`}
                download
              >
                <Paperclip size={17} />
                {item.path}
                <span>{Math.ceil(item.size / 1024)} KiB</span>
              </a>
            ))}
          </section>
        )}
      </main>
      {dialog && (
        <div
          className="dialog-backdrop"
          onMouseDown={(e) => {
            if (e.target === e.currentTarget) setDialog(null);
          }}
        >
          <dialog
            open
            aria-modal="true"
            aria-label={dialog.title}
            onKeyDown={(e) => {
              if (e.key !== "Tab") return;
              const items = Array.from(
                e.currentTarget.querySelectorAll<HTMLElement>(
                  "button:not(:disabled),input,select,textarea,a[href]",
                ),
              );
              const first = items[0],
                last = items[items.length - 1];
              if (e.shiftKey && document.activeElement === first) {
                e.preventDefault();
                last?.focus();
              } else if (!e.shiftKey && document.activeElement === last) {
                e.preventDefault();
                first?.focus();
              }
            }}
          >
            <div className="dialog-title">
              <h2>{dialog.title}</h2>
              <button aria-label="Close dialog" onClick={() => setDialog(null)}>
                <X size={18} />
              </button>
            </div>
            {dialog.error && (
              <p role="status" className="notice">
                {dialog.error}
              </p>
            )}
            {dialog.fields && (
              <form
                key={dialog.fields.map((f) => `${f.id}:${f.value}`).join("|")}
                onSubmit={(e) => {
                  e.preventDefault();
                  void submitForm(e.currentTarget);
                }}
              >
                {dialog.fields.map((field) => (
                  <label key={field.id}>
                    {field.label}
                    {field.options ? (
                      <select name={field.id} defaultValue={field.value}>
                        {field.options.map((option: string) => (
                          <option key={option}>{option}</option>
                        ))}
                      </select>
                    ) : (
                      <input
                        name={field.id}
                        type={field.type || "text"}
                        defaultValue={
                          field.type === "checkbox"
                            ? undefined
                            : (field.value ?? "")
                        }
                        defaultChecked={
                          field.type === "checkbox" && !!field.value
                        }
                        list={
                          field.suggestions ? field.id + "-models" : undefined
                        }
                        onChange={
                          field.id === "path"
                            ? (e) => completePath(e.target.value)
                            : undefined
                        }
                        autoComplete={
                          field.type === "password" ? "new-password" : "off"
                        }
                      />
                    )}
                    {field.suggestions && (
                      <datalist id={field.id + "-models"}>
                        {field.suggestions.map((model: string) => (
                          <option key={model} value={model} />
                        ))}
                      </datalist>
                    )}
                  </label>
                ))}
                <div className="form-actions">
                  {dialog.command === "providers.connect" && (
                    <button
                      type="button"
                      onClick={(e) => submitForm(e.currentTarget.form!, true)}
                    >
                      Discover models
                    </button>
                  )}
                  <button className="primary" type="submit">
                    Apply
                  </button>
                </div>
              </form>
            )}
            {dialog.rows && (
              <>
                {dialog.kind === "notifications" && (
                  <select
                    aria-label="Notification filter"
                    value={inboxFilter}
                    onChange={(e) => setInboxFilter(e.target.value)}
                  >
                    <option value="all">All notifications</option>
                    <option value="unread">Unread</option>
                    <option value="error">Errors</option>
                    <option value="run">Current run</option>
                  </select>
                )}
                <input
                  aria-label="Filter items"
                  placeholder="Search…"
                  value={filter}
                  onChange={(e) => setFilter(e.target.value)}
                />
                <div className="dialog-list">
                  {dialog.rows
                    .filter(
                      (row) =>
                        (dialog.kind !== "notifications" ||
                          inboxFilter === "all" ||
                          (inboxFilter === "unread" && row.unread) ||
                          (inboxFilter === "error" &&
                            ["error", "critical"].includes(row.severity)) ||
                          (inboxFilter === "run" &&
                            row.run_id === state.run_name)) &&
                        text(row).toLowerCase().includes(filter.toLowerCase()),
                    )
                    .map((row, i) =>
                      dialog.kind === "notifications" ? (
                        <article
                          className={`notification ${row.unread ? "unread" : ""}`}
                          key={row.id}
                        >
                          <strong>{row.title}</strong>
                          <p>{row.detail}</p>
                          <small>
                            {row.severity} · {row.count || 1} events
                          </small>
                          <div>
                            <button
                              onClick={() =>
                                perform("notifications.manage", {
                                  operation: "read",
                                  id: row.id,
                                })
                                  .then(openInbox)
                                  .catch(() => {})
                              }
                            >
                              Mark read
                            </button>
                            <button
                              onClick={() =>
                                perform("notifications.manage", {
                                  operation: "dismiss",
                                  id: row.id,
                                })
                                  .then(openInbox)
                                  .catch(() => {})
                              }
                            >
                              Dismiss
                            </button>
                            {row.actions?.map((action: Row, index: number) => (
                              <button
                                key={index}
                                onClick={() =>
                                  perform("notifications.manage", {
                                    operation: "action",
                                    id: row.id,
                                    index,
                                  })
                                    .then((result) => {
                                      if (result.action === "open_routes")
                                        void openProviders();
                                      else if (
                                        result.action === "retry_route_test"
                                      )
                                        void perform("providers.test").catch(
                                          () => {},
                                        );
                                      else if (result.action === "dismiss") {
                                        void perform("notifications.manage", {
                                          operation: "dismiss",
                                          id: result.target,
                                        })
                                          .then(openInbox)
                                          .catch(() => {});
                                      } else {
                                        if (result.action === "open_agent")
                                          setSelectedAgent(result.target);
                                        setDialog(null);
                                        setView(
                                          result.action === "open_finding"
                                            ? "findings"
                                            : "workspace",
                                        );
                                      }
                                    })
                                    .catch(() => {})
                                }
                              >
                                {action.label || action.action}
                              </button>
                            ))}
                          </div>
                        </article>
                      ) : (
                        <button
                          className="list-row"
                          key={row.id || i}
                          onClick={() => choose(row)}
                        >
                          <span>{label(row)}</span>
                          <small>
                            {row.source || row.description || row.apply}
                          </small>
                        </button>
                      ),
                    )}
                </div>
              </>
            )}
          </dialog>
        </div>
      )}
    </div>
  );
}
