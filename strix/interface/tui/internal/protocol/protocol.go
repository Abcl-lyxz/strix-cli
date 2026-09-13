package protocol

import "encoding/json"

const Version = 7

var Capabilities = []string{
	"state-revisions",
	"collection-deltas",
	"structured-command-errors",
	"agents-collection",
	"interactive-configuration",
	"large-user-prompts",
	"model-route-pools",
	"notification-inbox",
	"storage-locations",
	"workspace-forms",
	"attachments",
	"provider-discovery",
}

type Envelope struct {
	Version   int             `json:"version"`
	Type      string          `json:"type"`
	RequestID string          `json:"request_id,omitempty"`
	Payload   json.RawMessage `json:"payload"`
}

type Message struct {
	ID    string `json:"id"`
	Text  string `json:"text"`
	Level string `json:"level"`
}

type Agent struct {
	ID           string  `json:"id"`
	Name         string  `json:"name"`
	ParentID     *string `json:"parent_id"`
	Status       string  `json:"status"`
	ErrorMessage string  `json:"error_message"`
	WaitKind     string  `json:"wait_kind"`
}

// Connection is one MCP connection the run may reach, as the backend projects
// it for the sidebar's MCP panel. Non-secret by construction: only the display
// name, how many tools the connection offers, and whether its live session has
// died (its reconnect-retry gave up). "In use" is not carried here; the client
// derives it from the connection-tagged tool-call events in the event stream.
type Connection struct {
	Name      string `json:"name"`
	ToolCount int    `json:"tool_count"`
	Dead      bool   `json:"dead"`
}

type Event struct {
	ID        string         `json:"id"`
	Type      string         `json:"type"`
	AgentID   string         `json:"agent_id"`
	Timestamp string         `json:"timestamp"`
	Version   int            `json:"version"`
	Data      map[string]any `json:"data"`
}

type Hello struct {
	Capabilities []string `json:"capabilities"`
}

type Snapshot struct {
	EditorCommand       string           `json:"editor_command"`
	Attachments         []map[string]any `json:"attachments"`
	RecentRuns          []map[string]any `json:"recent_runs"`
	SetupMode           bool             `json:"setup_mode"`
	ScanStarted         bool             `json:"scan_started"`
	ScanState           string           `json:"scan_state"`
	Targets             []string         `json:"targets"`
	TargetCount         int              `json:"target_count"`
	WorkingDir          string           `json:"working_dir"`
	PendingMount        string           `json:"pending_mount"`
	Instruction         string           `json:"instruction"`
	ScanMode            string           `json:"scan_mode"`
	MaxBudgetUSD        *float64         `json:"max_budget_usd"`
	MaxTurns            int              `json:"max_turns"`
	MaxAgents           int              `json:"max_agents"`
	ScopeMode           string           `json:"scope_mode"`
	DiffBase            string           `json:"diff_base"`
	Model               string           `json:"model"`
	ModelWarning        string           `json:"model_warning"`
	APIKeyConfigured    bool             `json:"api_key_configured"`
	APIBase             string           `json:"api_base"`
	ReasoningEffort     string           `json:"reasoning_effort"`
	StreamingEnabled    bool             `json:"streaming_enabled"`
	PromptCache         bool             `json:"prompt_cache"`
	LLMTimeout          int              `json:"llm_timeout"`
	MaxToolCallsPerTurn int              `json:"max_tool_calls_per_turn"`
	MaxContextImages    int              `json:"max_context_images"`
	ConfigEnvOverride   bool             `json:"config_env_override"`
	SelectedRoute       string           `json:"selected_route"`
	NotificationUnread  int              `json:"notification_unread"`
	CaidoURL            string           `json:"caido_url"`
	Messages            []Message        `json:"messages"`
	Agents              []Agent          `json:"-"`
	Events              []Event          `json:"-"`
	Vulnerabilities     []map[string]any `json:"-"`
	Usage               map[string]any   `json:"usage"`
	Subscription        bool             `json:"subscription"`
	Connections         []Connection     `json:"connections"`
	ViewerStatus        string           `json:"viewer_status"`
	ViewerURL           *string          `json:"viewer_url"`
	Error               *string          `json:"error"`
	ProjectionTruncated bool             `json:"projection_truncated"`
}

type StateUpdate struct {
	Revision int      `json:"revision"`
	State    Snapshot `json:"state"`
}

type CollectionBootstrap struct {
	Collection string            `json:"collection"`
	Revision   int               `json:"revision"`
	Cursor     int               `json:"cursor"`
	NextCursor int               `json:"next_cursor"`
	Done       bool              `json:"done"`
	Items      []json.RawMessage `json:"items"`
}

type CollectionOperation struct {
	Op   string          `json:"op"`
	ID   string          `json:"id,omitempty"`
	Item json.RawMessage `json:"item"`
}

type CollectionDelta struct {
	Collection   string                `json:"collection"`
	BaseRevision int                   `json:"base_revision"`
	Revision     int                   `json:"revision"`
	Cursor       int                   `json:"cursor"`
	NextCursor   int                   `json:"next_cursor"`
	Done         bool                  `json:"done"`
	Operations   []CollectionOperation `json:"operations"`
}

type CommandError struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	Retryable bool   `json:"retryable"`
}

type CommandResult struct {
	OK      bool            `json:"ok"`
	Command string          `json:"command"`
	Result  json.RawMessage `json:"result"`
	Error   *CommandError   `json:"error"`
}
