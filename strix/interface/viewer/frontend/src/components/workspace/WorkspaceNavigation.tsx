import {
  Activity,
  Bell,
  FolderOpen,
  History,
  Paperclip,
  Plus,
  Search,
  Settings,
  Sliders,
} from "lucide-react";
import type { LucideIcon } from "lucide-react";

type Props = {
  view: string;
  unread: number;
  onView: (view: string) => void;
  onNewScan: () => void;
  onInbox: () => void;
  onSettings: () => void;
  onCommands: () => void;
};

const destinations: Array<[string, string, LucideIcon]> = [
  ["overview", "Overview", Sliders],
  ["workspace", "Workspace", Activity],
  ["findings", "Findings", FolderOpen],
  ["evidence", "Evidence & reports", Paperclip],
  ["history", "History", History],
];

export function WorkspaceNavigation({
  view,
  unread,
  onView,
  onNewScan,
  onInbox,
  onSettings,
  onCommands,
}: Props) {
  return (
    <aside className="workspace-nav">
      <div className="brand">
        <Activity size={24} />
        <strong>strix</strong>
        <span>LOCAL</span>
      </div>
      <button className="new-scan" onClick={onNewScan}>
        <Plus size={17} />
        New scan
      </button>
      {destinations.map(([id, title, Icon]) => (
        <button
          key={id}
          aria-current={view === id ? "page" : undefined}
          onClick={() => onView(id)}
        >
          <Icon size={17} />
          {title}
        </button>
      ))}
      <div className="nav-bottom">
        <button onClick={onInbox}>
          <Bell size={17} />
          Notifications <span className="count">{unread}</span>
        </button>
        <button onClick={onSettings}>
          <Settings size={17} />
          Settings
        </button>
        <button onClick={onCommands}>
          <Search size={17} />
          Commands <kbd>Ctrl K</kbd>
        </button>
      </div>
    </aside>
  );
}
