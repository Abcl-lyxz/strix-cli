export type JsonPrimitive = string | number | boolean | null;
export type JsonValue = JsonPrimitive | JsonValue[] | { [key: string]: JsonValue };

export interface WorkspaceRow {
  [key: string]: unknown;
  id?: string;
  name?: string;
  title?: string;
  label?: string;
  path?: string;
  status?: string;
  severity?: string;
  description?: string;
  detail?: string;
  text?: string;
  level?: string;
  role?: string;
  workspace_path?: string;
  type?: string;
  value?: unknown;
  options?: string[];
  suggestions?: string[];
  actions?: Array<{ id?: string; action?: string; label?: string; target?: string }>;
  action?: string;
  target?: string;
  source?: string;
  count?: number;
  size?: number;
  unread?: boolean;
  enabled?: boolean;
  apply?: boolean;
  base_url?: string;
  priority?: number;
  max_concurrency?: number;
  rpm?: number | null;
  tpm?: number | null;
  run_id?: string;
  agent_id?: string;
  wait_kind?: string;
  content?: unknown;
  message?: unknown;
  tool_name?: string;
  data?: WorkspaceRow;
  models?: WorkspaceRow[];
  paths?: WorkspaceRow[];
  runs?: WorkspaceRow[];
  artifacts?: WorkspaceRow[];
  agents?: WorkspaceRow[];
  events?: WorkspaceRow[];
  findings?: WorkspaceRow[];
  runRecord?: WorkspaceRow;
  initial_run?: string;
  start_time?: string;
  end_time?: string;
  cve?: string;
  cwe?: string;
  cvss?: number;
  known_exploited?: boolean;
}

export interface WorkspaceAgent extends WorkspaceRow {
  id: string;
  name: string;
  parent_id: string | null;
  status: string;
  created_at: string;
  updated_at: string;
}

export interface WorkspaceEvent extends WorkspaceRow {
  id: string;
  type: "chat" | "tool";
  agent_id: string;
  timestamp: string;
  version: number;
  data: Record<string, unknown>;
}

export interface HistoricalRun extends WorkspaceRow {
  name: string;
  agents?: WorkspaceAgent[];
  events?: WorkspaceEvent[];
  findings?: WorkspaceRow[];
  runRecord?: WorkspaceRow;
}

export interface WorkspaceState extends WorkspaceRow {
  setup_mode?: boolean;
  scan_state?: string;
  run_name?: string;
  scan_mode?: string;
  max_budget_usd?: number | null;
  max_turns?: number;
  max_agents?: number;
  scope_mode?: string;
  diff_base?: string | null;
  selected_route?: string;
  model?: string;
  route_health?: Array<{
    health?: string;
    circuit_state?: string;
    last_error?: { detail?: string };
    cooldown_remaining?: number;
    queued?: number;
    active?: number;
    effective_concurrency?: number;
    context_usage_tokens?: number;
    context_window_tokens?: number;
    next_retry_seconds?: number;
    retry_waste_tokens?: number;
  }>;
  notification_unread?: number;
  recovery?: { title?: string; detail?: string; agent_id?: string };
  api_key_configured?: boolean;
  target_count?: number;
  recent_runs?: WorkspaceRow[];
  messages?: WorkspaceRow[];
  scan_started?: boolean;
  pending_mount?: string;
  targets?: string[];
  target_ids?: string[];
  agent_graph?: WorkspaceRow;
}

export interface WorkspaceStreamEnvelope {
  reset?: boolean;
  state?: WorkspaceState;
  events?: WorkspaceEvent[];
  agents?: WorkspaceAgent[];
  findings?: WorkspaceRow[];
  attachments?: WorkspaceRow[];
}

export interface WorkspaceDialog {
  title: string;
  command?: string;
  payload?: WorkspaceRow;
  fields?: WorkspaceFormField[];
  rows?: WorkspaceDialogRow[];
  kind?: string;
  error?: string;
}

export interface WorkspaceFormField extends WorkspaceRow {
  id: string;
  label: string;
  value?: string | number | boolean | null;
  type?: string;
  options?: string[];
  suggestions?: string[];
}

export interface WorkspaceDialogRow extends WorkspaceRow {
  run?: () => void;
}

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function parseAgent(value: Record<string, unknown>): WorkspaceAgent | null {
  if (typeof value.id !== "string") return null;
  return {
    ...value,
    id: value.id,
    name: typeof value.name === "string" ? value.name : value.id,
    parent_id: typeof value.parent_id === "string" ? value.parent_id : null,
    status: typeof value.status === "string" ? value.status : "unknown",
    created_at: typeof value.created_at === "string" ? value.created_at : "",
    updated_at: typeof value.updated_at === "string" ? value.updated_at : "",
  };
}

function parseEvent(value: Record<string, unknown>): WorkspaceEvent | null {
  if (typeof value.id !== "string") return null;
  return {
    ...value,
    id: value.id,
    type: value.type === "tool" ? "tool" : "chat",
    agent_id: typeof value.agent_id === "string" ? value.agent_id : "",
    timestamp: typeof value.timestamp === "string" ? value.timestamp : "",
    version: typeof value.version === "number" ? value.version : 0,
    data: isRecord(value.data) ? value.data : {},
  };
}

export function parseWorkspaceStream(value: unknown): WorkspaceStreamEnvelope | null {
  if (!isRecord(value)) return null;
  const envelope: WorkspaceStreamEnvelope = { reset: value.reset === true };
  if (isRecord(value.state)) envelope.state = value.state as WorkspaceState;
  const events = value.events;
  if (Array.isArray(events))
    envelope.events = events.filter(isRecord).map(parseEvent).filter((row): row is WorkspaceEvent => row !== null);
  const agents = value.agents;
  if (Array.isArray(agents))
    envelope.agents = agents.filter(isRecord).map(parseAgent).filter((row): row is WorkspaceAgent => row !== null);
  for (const key of ["findings", "attachments"] as const) {
    const rows = value[key];
    if (Array.isArray(rows) && rows.every(isRecord)) envelope[key] = rows as WorkspaceRow[];
  }
  return envelope;
}
