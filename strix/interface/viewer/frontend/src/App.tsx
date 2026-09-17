import { useCallback, useEffect, useMemo, useState } from "react";
import { Activity, Search, X } from "lucide-react";

import AgentGraph from "@/components/live/AgentGraph";
import { AgentTranscript, buildGraphAgents } from "@/components/live/AgentTranscript";
import { IssueSeveritySummary } from "@/components/IssueSeveritySummary";
import { RunDetails } from "@/components/RunDetails";
import VulnerabilityDetail from "@/components/vulnerability/VulnerabilityDetail";
import { normalizeVulnerability } from "@/lib/local-run-parser";
import type { Vulnerability } from "@/types/issues";
import { requestJson } from "@/workspace/apiClient";
import type {
  HistoricalRun,
  WorkspaceAgent,
  WorkspaceEvent,
  WorkspaceRow,
} from "@/workspace/contracts";
import { mergeEvents } from "@/workspace/store";
import { useWorkspaceStream } from "@/workspace/useWorkspaceStream";

import "./workspace.css";

type Row = WorkspaceRow;
type View = "workspace" | "overview" | "history" | "evidence";

const text = (value: unknown) =>
  typeof value === "string" ? value : JSON.stringify(value, null, 2);

async function api<T = Row>(path: string): Promise<T> {
  return requestJson<T>(path);
}

export { mergeEvents };

export default function App() {
  const [view, setView] = useState<View>("workspace");
  const [runRecord, setRunRecord] = useState<Row>({});
  const [runs, setRuns] = useState<Row[]>([]);
  const [artifacts, setArtifacts] = useState<Row[]>([]);
  const [historical, setHistorical] = useState<HistoricalRun | null>(null);
  const [selectedAgent, setSelectedAgent] = useState<string | null>(null);
  const [selectedFinding, setSelectedFinding] = useState<string | null>(null);
  const [showGraph, setShowGraph] = useState(false);
  const [search, setSearch] = useState("");
  const [error, setError] = useState("");
  const onStreamError = useCallback((message: string) => setError(message), []);
  const { state, events, agents, findings, online } = useWorkspaceStream(onStreamError);

  const runQuery = historical ? `?run=${encodeURIComponent(historical.name)}` : "";

  useEffect(() => {
    const url = new URL(location.href);
    url.searchParams.delete("token");
    history.replaceState(null, "", url);
    api<{ initial_run?: string }>("/api/capabilities")
      .then((value) => {
        if (value.initial_run) void browse({ name: value.initial_run });
      })
      .catch(() => {});
  }, []);

  useEffect(() => {
    if (view === "history") {
      api<{ runs?: Row[] }>("/api/runs")
        .then((value) => setRuns(value.runs ?? []))
        .catch((cause: Error) => setError(cause.message));
    }
  }, [view, state.scan_state]);

  useEffect(() => {
    if (view === "evidence") {
      api<{ artifacts?: Row[] }>("/api/artifacts" + runQuery)
        .then((value) => setArtifacts(value.artifacts ?? []))
        .catch((cause: Error) => setError(cause.message));
    }
  }, [view, runQuery, state.scan_state]);

  useEffect(() => {
    if (!historical && state.run_name) {
      api("/api/run")
        .then(setRunRecord)
        .catch(() => {});
    }
  }, [historical, state.run_name, state.scan_state]);

  async function browse(run: Row) {
    if (!run.name) return;
    try {
      const query = `?run=${encodeURIComponent(run.name)}`;
      const [transcript, reports, record] = await Promise.all([
        api<{ agents?: WorkspaceAgent[]; events?: WorkspaceEvent[] }>(
          "/api/transcript" + query,
        ),
        api<Row[]>("/api/vulnerabilities" + query),
        api<Row>("/api/run" + query),
      ]);
      setHistorical({
        ...run,
        name: run.name,
        agents: transcript.agents ?? [],
        events: transcript.events ?? [],
        findings: reports,
        runRecord: record,
      });
      setView("overview");
    } catch (cause) {
      setError((cause as Error).message);
    }
  }

  const displayedAgents = historical?.agents ?? agents;
  const displayedEvents = historical?.events ?? events;
  const displayedFindings = historical?.findings ?? findings;
  const displayedRun = historical?.runRecord ?? runRecord;
  const graph = useMemo(
    () => buildGraphAgents(displayedAgents, displayedEvents),
    [displayedAgents, displayedEvents],
  );
  const normalizedFindings = useMemo<Vulnerability[]>(
    () =>
      displayedFindings.map((finding: Row, index: number) =>
        normalizeVulnerability(
          finding,
          index,
          String(historical?.name || state.run_name || "") || null,
        ),
      ),
    [displayedFindings, historical?.name, state.run_name],
  );
  const findingSummary = useMemo(
    () => ({
      total: normalizedFindings.length,
      critical: normalizedFindings.filter((item) => item.severity === "critical").length,
      high: normalizedFindings.filter((item) => item.severity === "high").length,
      medium: normalizedFindings.filter((item) => item.severity === "medium").length,
      low: normalizedFindings.filter((item) => item.severity === "low").length,
    }),
    [normalizedFindings],
  );
  const activeFinding =
    normalizedFindings.find((item) => item.id === selectedFinding) ?? null;
  const visibleEvents = displayedEvents
    .filter(
      (event: Row) =>
        (!selectedAgent || event.agent_id === selectedAgent) &&
        text(event).toLowerCase().includes(search.toLowerCase()),
    )
    .slice(-300);
  const runDuration = useMemo(() => {
    const start = Date.parse(String(displayedRun.start_time || ""));
    const end = displayedRun.end_time
      ? Date.parse(String(displayedRun.end_time))
      : Date.now();
    return Number.isFinite(start) && Number.isFinite(end) && end >= start
      ? Math.round((end - start) / 1000)
      : null;
  }, [displayedRun]);

  return (
    <div className="workspace-shell">
      <nav className="workspace-nav" aria-label="Read-only viewer navigation">
        <div className="brand">
          <strong>Strix</strong><span>VIEWER</span>
        </div>
        <button onClick={() => setView("workspace")}>Transcript</button>
        <button onClick={() => setView("overview")}>Findings</button>
        <button onClick={() => setView("evidence")}>Artifacts & reports</button>
        <button onClick={() => setView("history")}>Run history</button>
        <p className="muted">Read-only. Use the terminal TUI to control Strix.</p>
      </nav>
      <main className="workspace-main">
        <header>
          <div>
            <span className={online ? "status-dot online" : "status-dot"} />
            {online ? state.scan_state || "Ready" : "Reconnecting…"}
            <span className="muted"> / {historical?.name || state.run_name || "No run"}</span>
          </div>
          <span className="route-health">read-only live view</span>
        </header>
        {error && (
          <div role="alert" className="error-banner">
            {error}
            <button aria-label="Dismiss error" onClick={() => setError("")}><X size={16} /></button>
          </div>
        )}
        {view === "workspace" && (
          <section className="workspace-feed">
            {!displayedEvents.length && (
              <div className="welcome"><Activity size={38} /><h1>Live transcript</h1><p>Events appear here as the terminal-controlled scan runs.</p></div>
            )}
            {!!displayedAgents.length && (
              <>
                <div className="agent-strip">
                  <button onClick={() => setShowGraph(!showGraph)}>{showGraph ? "Hide graph" : "Agent graph"}</button>
                  <button onClick={() => setSelectedAgent(null)}>All agents</button>
                  {displayedAgents.map((agent) => (
                    <button key={agent.id} onClick={() => setSelectedAgent(agent.id)} aria-pressed={selectedAgent === agent.id}>
                      {agent.name} <small>{agent.status}</small>
                    </button>
                  ))}
                </div>
                {showGraph && <div style={{ height: 360 }}><AgentGraph agents={graph} selectedAgentId={selectedAgent} onSelectAgent={setSelectedAgent} eventsLoaded eventsEmpty={!displayedEvents.length} /></div>}
              </>
            )}
            {!!displayedEvents.length && (
              <label className="search"><Search size={16} /><input aria-label="Search transcript" value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search transcript and tool output" /></label>
            )}
            {visibleEvents.map((event, index) => {
              const data = event.data || event;
              return event.type === "tool" ? (
                <AgentTranscript key={event.id || index} agent={displayedAgents.find((agent) => agent.id === event.agent_id) ?? { id: event.agent_id, name: event.agent_id, parent_id: null, status: "running", created_at: event.timestamp, updated_at: event.timestamp }} events={[event]} showHeader={false} />
              ) : (
                <article className="event" key={event.id || index}>
                  <div className="event-label">{text(data.role || data.name || event.type)}<small>{event.agent_id}</small></div>
                  <pre>{text(data.content || data.text || data.message || data)}</pre>
                </article>
              );
            })}
          </section>
        )}
        {view === "overview" && (
          <section className="page overview-page">
            <h1>Security findings</h1>
            <IssueSeveritySummary findings={findingSummary} />
            {!normalizedFindings.length && <p>No verified findings recorded.</p>}
            <div className="overview-findings">
              {normalizedFindings.map((finding) => (
                <button key={finding.id} className="finding-row" onClick={() => setSelectedFinding(finding.id)}>
                  <span className={`severity ${finding.severity}`}>{finding.severity}</span><strong>{finding.title}</strong><span>{finding.cvss != null ? `CVSS ${finding.cvss}` : "CVSS pending"}</span>
                </button>
              ))}
            </div>
            <RunDetails raw={displayedRun} durationSeconds={runDuration} />
            {activeFinding && <div className="finding-modal" role="dialog" aria-modal="true"><div className="finding-modal-card"><button className="finding-modal-close" aria-label="Close finding" onClick={() => setSelectedFinding(null)}><X size={18} /></button><VulnerabilityDetail vulnerability={activeFinding} /></div></div>}
          </section>
        )}
        {view === "history" && <section className="page"><h1>Local run history</h1>{runs.map((run) => <button className="run-row" key={run.name} onClick={() => void browse(run)}><strong>{run.name}</strong><span>{run.status}</span></button>)}</section>}
        {view === "evidence" && <section className="page"><h1>Artifacts & reports</h1><a className="artifact" href={`/api/report/pdf${runQuery}`} download>Download PDF report</a>{artifacts.filter((artifact) => artifact.path).map((artifact) => <a className="artifact" key={artifact.path} href={`/api/artifact?path=${encodeURIComponent(artifact.path ?? "")}${historical ? `&run=${encodeURIComponent(historical.name)}` : ""}`} download>{artifact.path}<span>{Math.ceil((artifact.size ?? 0) / 1024)} KiB</span></a>)}</section>}
      </main>
    </div>
  );
}
