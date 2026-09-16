import { X } from "lucide-react";
import type {
  WorkspaceDialog as Dialog,
  WorkspaceDialogRow,
  WorkspaceRow as Row,
} from "@/workspace/contracts";

type Props = {
  dialog: Dialog;
  inboxFilter: string;
  filter: string;
  runName?: string;
  setDialog: (dialog: Dialog | null) => void;
  setInboxFilter: (filter: string) => void;
  setFilter: (filter: string) => void;
  completePath: (path: string) => void;
  submitForm: (form: HTMLFormElement, discover?: boolean) => Promise<void>;
  choose: (row: WorkspaceDialogRow) => void;
  perform: (name: string, payload?: Row) => Promise<Row>;
  openInbox: () => void;
  openProviders: () => void;
  selectAgent: (id: string) => void;
  selectView: (view: string) => void;
};

const label = (row: Row) =>
  String(row.label || row.title || row.name || row.id || row.path || "Item");
const text = (value: unknown) =>
  typeof value === "string" ? value : JSON.stringify(value, null, 2);

export function WorkspaceDialog({
  dialog,
  inboxFilter,
  filter,
  runName,
  setDialog,
  setInboxFilter,
  setFilter,
  completePath,
  submitForm,
  choose,
  perform,
  openInbox,
  openProviders,
  selectAgent,
  selectView,
}: Props) {
  return (
    <div
      className="dialog-backdrop"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) setDialog(null);
      }}
    >
      <dialog
        open
        aria-modal="true"
        aria-label={dialog.title}
        onKeyDown={(event) => {
          if (event.key !== "Tab") return;
          const items = Array.from(
            event.currentTarget.querySelectorAll<HTMLElement>(
              "button:not(:disabled),input,select,textarea,a[href]",
            ),
          );
          const first = items[0];
          const last = items[items.length - 1];
          if (event.shiftKey && document.activeElement === first) {
            event.preventDefault();
            last?.focus();
          } else if (!event.shiftKey && document.activeElement === last) {
            event.preventDefault();
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
            key={dialog.fields.map((field) => `${field.id}:${field.value}`).join("|")}
            onSubmit={(event) => {
              event.preventDefault();
              void submitForm(event.currentTarget);
            }}
          >
            {dialog.fields.map((field) => (
              <label key={field.id}>
                {field.label}
                {field.options ? (
                  <select
                    name={field.id}
                    defaultValue={
                      typeof field.value === "string" || typeof field.value === "number"
                        ? field.value
                        : undefined
                    }
                  >
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
                        : typeof field.value === "string" || typeof field.value === "number"
                          ? field.value
                          : ""
                    }
                    defaultChecked={field.type === "checkbox" && !!field.value}
                    list={field.suggestions ? `${field.id}-models` : undefined}
                    onChange={
                      field.id === "path"
                        ? (event) => completePath(event.target.value)
                        : undefined
                    }
                    autoComplete={field.type === "password" ? "new-password" : "off"}
                  />
                )}
                {field.suggestions && (
                  <datalist id={`${field.id}-models`}>
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
                  onClick={(event) => void submitForm(event.currentTarget.form!, true)}
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
                onChange={(event) => setInboxFilter(event.target.value)}
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
              onChange={(event) => setFilter(event.target.value)}
            />
            <div className="dialog-list">
              {dialog.rows
                .filter(
                  (row) =>
                    (dialog.kind !== "notifications" ||
                      inboxFilter === "all" ||
                      (inboxFilter === "unread" && row.unread) ||
                      (inboxFilter === "error" &&
                        ["error", "critical"].includes(row.severity ?? "")) ||
                      (inboxFilter === "run" && row.run_id === runName)) &&
                    text(row).toLowerCase().includes(filter.toLowerCase()),
                )
                .map((row, index) =>
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
                            void perform("notifications.manage", {
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
                            void perform("notifications.manage", {
                              operation: "dismiss",
                              id: row.id,
                            })
                              .then(openInbox)
                              .catch(() => {})
                          }
                        >
                          Dismiss
                        </button>
                        {row.actions?.map((action: Row, actionIndex: number) => (
                          <button
                            key={actionIndex}
                            onClick={() =>
                              void perform("notifications.manage", {
                                operation: "action",
                                id: row.id,
                                index: actionIndex,
                              })
                                .then((result) => {
                                  if (result.action === "open_routes") void openProviders();
                                  else if (result.action === "retry_route_test")
                                    void perform("providers.test").catch(() => {});
                                  else if (result.action === "dismiss")
                                    void perform("notifications.manage", {
                                      operation: "dismiss",
                                      id: result.target,
                                    })
                                      .then(openInbox)
                                      .catch(() => {});
                                  else {
                                    if (
                                      result.action === "open_agent" &&
                                      typeof result.target === "string"
                                    )
                                      selectAgent(result.target);
                                    setDialog(null);
                                    selectView(
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
                      key={row.id || index}
                      onClick={() => choose(row)}
                    >
                      <span>{label(row)}</span>
                      <small>{row.source || row.description || row.apply}</small>
                    </button>
                  ),
                )}
            </div>
          </>
        )}
      </dialog>
    </div>
  );
}
