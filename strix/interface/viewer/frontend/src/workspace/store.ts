import type {
  WorkspaceAgent,
  WorkspaceEvent,
  WorkspaceRow,
  WorkspaceState,
  WorkspaceStreamEnvelope,
} from "./contracts";

export interface WorkspaceStore {
  state: WorkspaceState;
  events: WorkspaceEvent[];
  agents: WorkspaceAgent[];
  findings: WorkspaceRow[];
  attachments: WorkspaceRow[];
  online: boolean;
}

export type WorkspaceAction =
  | { type: "stream.open" }
  | { type: "stream.close" }
  | { type: "stream.message"; envelope: WorkspaceStreamEnvelope };

export const initialWorkspaceStore: WorkspaceStore = {
  state: { setup_mode: true },
  events: [],
  agents: [],
  findings: [],
  attachments: [],
  online: false,
};

export function mergeEvents<T extends WorkspaceRow>(
  previous: T[],
  incoming: T[],
  reset = false,
): T[] {
  const map = new Map((reset ? [] : previous).map((item) => [item.id, item]));
  incoming.forEach((item) => map.set(item.id, item));
  return [...map.values()].slice(-5000);
}

export function workspaceReducer(
  store: WorkspaceStore,
  action: WorkspaceAction,
): WorkspaceStore {
  if (action.type === "stream.open") return { ...store, online: true };
  if (action.type === "stream.close") return { ...store, online: false };
  const envelope = action.envelope;
  return {
    state: envelope.state ?? store.state,
    events: envelope.events
      ? mergeEvents(store.events, envelope.events, envelope.reset)
      : store.events,
    agents: envelope.agents ?? store.agents,
    findings: envelope.findings ?? store.findings,
    attachments: envelope.attachments ?? store.attachments,
    online: store.online,
  };
}
