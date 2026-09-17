package app

import (
	"encoding/json"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"
	"github.com/usestrix/strix/tui/internal/protocol"
)

func TestLegacyAPIKeyCommandFailsWithoutDispatch(t *testing.T) {
	connection := &recordingConn{}
	model := New(&Client{conn: connection})
	model.width, model.height = 100, 35
	model.showSplash, model.ready = false, true
	model.snapshot = protocol.Snapshot{SetupMode: true}

	updated, cmd, handled := model.submitSlashCommand("/apikey")
	model = updated.(Model)
	if !handled || cmd != nil || connection.Len() != 0 {
		t.Fatalf("legacy /apikey dispatched work: handled=%v cmd=%v", handled, cmd)
	}
}

func TestSlashModelsOpensProviderModelWorkspace(t *testing.T) {
	connection := &recordingConn{}
	model := New(&Client{conn: connection})
	model.snapshot = protocol.Snapshot{SetupMode: true}

	_, cmd, handled := model.submitSlashCommand("/models")
	if !handled || cmd == nil {
		t.Fatal("models command was not handled")
	}
	envelope := commandFromCmd(t, cmd, connection)
	if envelope.Type != "providers.list" {
		t.Fatalf("command type = %q, want providers.list", envelope.Type)
	}
}

func TestUpdateCommandAndNotificationActionUseTheSameUpdater(t *testing.T) {
	commandModel, commandConnection := newCommandTestModel(t)
	_, command, handled := commandModel.submitSlashCommand("/update")
	if !handled || command == nil {
		t.Fatal("update command was not handled")
	}
	commandEnvelope := commandFromCmd(t, command, commandConnection)

	actionModel, actionConnection := newCommandTestModel(t)
	actionModel.modal = modalWorkspace
	actionModel.dialog = workspaceDialog{Kind: "notifications"}
	action := handleCommandResult(t, &actionModel, "notifications.manage", map[string]any{
		"action": "start_update",
	})
	if action == nil {
		t.Fatal("notification update action did not dispatch")
	}
	actionEnvelope := commandFromCmd(t, action, actionConnection)

	if commandEnvelope.Type != "update.start" || actionEnvelope.Type != commandEnvelope.Type {
		t.Fatalf("updater mismatch: command=%q notification=%q", commandEnvelope.Type, actionEnvelope.Type)
	}
}

func TestSlashAgentsStopUsesTypedAgentCommand(t *testing.T) {
	connection := &recordingConn{}
	model := New(&Client{conn: connection})
	model.snapshot = protocol.Snapshot{SetupMode: true}

	_, cmd, handled := model.submitSlashCommand("/agents stop child-1")
	if !handled || cmd == nil {
		t.Fatal("agents command was not handled")
	}
	envelope := commandFromCmd(t, cmd, connection)
	if envelope.Type != "agent.stop" {
		t.Fatalf("command type = %q, want agent.stop", envelope.Type)
	}
	var payload map[string]any
	if err := json.Unmarshal(envelope.Payload, &payload); err != nil {
		t.Fatal(err)
	}
	if payload["agent_id"] != "child-1" {
		t.Fatalf("agent payload = %#v", payload)
	}
}

func TestSlashFindSendsWorkspaceCommand(t *testing.T) {
	connection := &recordingConn{}
	model := New(&Client{conn: connection})
	model.snapshot = protocol.Snapshot{SetupMode: true}

	_, cmd, handled := model.submitSlashCommand("/find ade")
	if !handled || cmd == nil {
		t.Fatal("find command was not handled")
	}
	envelope := commandFromCmd(t, cmd, connection)
	if envelope.Type != "workspace.find" {
		t.Fatalf("command type = %q, want workspace.find", envelope.Type)
	}
	var payload map[string]any
	if err := json.Unmarshal(envelope.Payload, &payload); err != nil {
		t.Fatal(err)
	}
	if payload["query"] != "ade" {
		t.Fatalf("find payload = %#v", payload)
	}
}

func TestWorkspaceSearchResultUsesExistingModalStyle(t *testing.T) {
	model, _ := newCommandTestModel(t)
	model.width, model.height = 100, 35
	result := map[string]any{
		"query":       "ade",
		"root":        "/workspace/project",
		"match_count": 1,
		"truncated":   false,
		"matches": []map[string]any{{
			"path": "src/main.py", "line": 12, "column": 4, "text": "value = ade",
		}},
	}

	handleCommandResult(t, &model, "workspace.find", result)

	if model.modal != modalWorkspaceSearch {
		t.Fatalf("search result modal = %v", model.modal)
	}
	view := ansi.Strip(model.modalView())
	for _, want := range []string{"Workspace search", "ade", "src/main.py:12:4", "value = ade"} {
		if !strings.Contains(view, want) {
			t.Fatalf("search modal missing %q: %s", want, view)
		}
	}
}

func TestTabCompletesSlashCommandBeforeChangingFocus(t *testing.T) {
	model := New(nil)
	model.showSplash, model.ready, model.focus = false, true, focusInput
	model.snapshot = protocol.Snapshot{SetupMode: true}
	model.input.SetValue("/rou")

	updated, cmd := model.updateMain(tea.KeyMsg{Type: tea.KeyTab})
	result := updated.(Model)
	if cmd != nil || result.input.Value() != "/router " || result.focus != focusInput {
		t.Fatalf("tab completion failed: value=%q focus=%v cmd=%v", result.input.Value(), result.focus, cmd)
	}
}

func TestUnknownAbsolutePathRemainsPromptText(t *testing.T) {
	model := New(nil)
	_, _, handled := model.submitSlashCommand("/workspace/source check auth")
	if handled {
		t.Fatal("absolute path was mistaken for a slash command")
	}
}

func TestMissingCommandArgumentOpensForm(t *testing.T) {
	connection := &recordingConn{}
	model := New(&Client{conn: connection})
	model.snapshot = protocol.Snapshot{SetupMode: true}
	updated, cmd, handled := model.submitSlashCommand("/attach")
	result := updated.(Model)
	if !handled || cmd != nil || connection.Len() != 0 || result.modal != modalWorkspace || result.dialog.Command != "attachments.add" {
		t.Fatalf("attach did not open a local form: %#v", result.dialog)
	}
}

func TestBareSlashOpensHelpInsteadOfScanningRoot(t *testing.T) {
	model := New(nil)
	model.snapshot = protocol.Snapshot{SetupMode: true}

	updated, cmd, handled := model.submitSlashCommand("/")
	result := updated.(Model)
	if !handled || cmd != nil || result.modal != modalHelp {
		t.Fatalf("bare slash did not open help: handled=%v cmd=%v modal=%v", handled, cmd, result.modal)
	}
}
