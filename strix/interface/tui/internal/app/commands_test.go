package app

import (
	"encoding/json"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"
	"github.com/usestrix/strix/tui/internal/protocol"
)

func TestAPIKeyCommandIsMaskedInComposerAndConfigView(t *testing.T) {
	model := New(nil)
	model.width, model.height = 100, 35
	model.showSplash, model.ready = false, true
	model.snapshot = protocol.Snapshot{SetupMode: true, APIKeyConfigured: true}
	model.input.SetValue("/apikey sk-super-secret")
	model.resizeViewport()

	view := ansi.Strip(model.View())
	if strings.Contains(view, "sk-super-secret") {
		t.Fatal("API key leaked in the rendered composer")
	}
	if !strings.Contains(view, "/apikey ") || !strings.Contains(view, "••••") {
		t.Fatalf("masked API key command is missing: %s", view)
	}

	model.openModal(modalConfig)
	config := ansi.Strip(model.modalView())
	if !strings.Contains(config, "configured (hidden)") || strings.Contains(config, "sk-super-secret") {
		t.Fatalf("config modal did not keep the key write-only: %s", config)
	}
}

func TestBareAPIKeyCommandOpensSecureModalAndSubmitsWriteOnlyValue(t *testing.T) {
	connection := &recordingConn{}
	model := New(&Client{conn: connection})
	model.width, model.height = 100, 35
	model.showSplash, model.ready = false, true
	model.snapshot = protocol.Snapshot{SetupMode: true}

	updated, cmd, handled := model.submitSlashCommand("/apikey")
	model = updated.(Model)
	if !handled || cmd != nil || model.modal != modalAPIKey {
		t.Fatalf("bare /apikey did not open secure modal: handled=%v cmd=%v modal=%v", handled, cmd, model.modal)
	}
	model.apiKeyInput.SetValue("sk-modal-secret")
	if view := ansi.Strip(model.modalView()); strings.Contains(view, "sk-modal-secret") || !strings.Contains(view, "••••") {
		t.Fatalf("secure modal leaked or failed to mask the key: %s", view)
	}

	updated, cmd = model.updateModal(tea.KeyMsg{Type: tea.KeyEnter})
	model = updated.(Model)
	if cmd == nil || model.modal != modalNone || model.apiKeyInput.Value() != "" {
		t.Fatalf("secure modal did not clear after submit: modal=%v value=%q", model.modal, model.apiKeyInput.Value())
	}
	envelope := commandFromCmd(t, cmd, connection)
	if envelope.Type != "config.update" {
		t.Fatalf("command type = %q, want config.update", envelope.Type)
	}
	var payload map[string]any
	if err := json.Unmarshal(envelope.Payload, &payload); err != nil {
		t.Fatal(err)
	}
	if payload["api_key"] != "sk-modal-secret" {
		t.Fatalf("API key payload = %#v", payload)
	}
}

func TestSlashModelSendsInteractiveConfigCommand(t *testing.T) {
	connection := &recordingConn{}
	model := New(&Client{conn: connection})
	model.snapshot = protocol.Snapshot{SetupMode: true}

	_, cmd, handled := model.submitSlashCommand("/model openrouter/openai/gpt-5.4")
	if !handled || cmd == nil {
		t.Fatal("model command was not handled")
	}
	envelope := commandFromCmd(t, cmd, connection)
	if envelope.Type != "config.update" {
		t.Fatalf("command type = %q, want config.update", envelope.Type)
	}
	var payload map[string]any
	if err := json.Unmarshal(envelope.Payload, &payload); err != nil {
		t.Fatal(err)
	}
	if payload["model"] != "openrouter/openai/gpt-5.4" {
		t.Fatalf("model payload = %#v", payload)
	}
}

func TestSlashScanControlsSendSetupConfiguration(t *testing.T) {
	connection := &recordingConn{}
	model := New(&Client{conn: connection})
	model.snapshot = protocol.Snapshot{SetupMode: true}

	_, cmd, handled := model.submitSlashCommand("/agents 7")
	if !handled || cmd == nil {
		t.Fatal("agents command was not handled")
	}
	envelope := commandFromCmd(t, cmd, connection)
	if envelope.Type != "setup.configure" {
		t.Fatalf("command type = %q, want setup.configure", envelope.Type)
	}
	var payload map[string]any
	if err := json.Unmarshal(envelope.Payload, &payload); err != nil {
		t.Fatal(err)
	}
	if payload["max_agents"] != float64(7) {
		t.Fatalf("max_agents payload = %#v", payload)
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
	model.input.SetValue("/reas")

	updated, cmd := model.updateMain(tea.KeyMsg{Type: tea.KeyTab})
	result := updated.(Model)
	if cmd != nil || result.input.Value() != "/reasoning " || result.focus != focusInput {
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

func TestMissingCommandArgumentDoesNotSendBackendCommand(t *testing.T) {
	connection := &recordingConn{}
	model := New(&Client{conn: connection})
	model.snapshot = protocol.Snapshot{SetupMode: true}

	updated, cmd, handled := model.submitSlashCommand("/target")
	if !handled || cmd != nil || connection.Len() != 0 {
		t.Fatalf("missing target reached backend: handled=%v cmd=%v frames=%d", handled, cmd, connection.Len())
	}
	if log := updated.(Model).setupLog; len(log) == 0 || !strings.Contains(ansi.Strip(log[len(log)-1]), "Usage") {
		t.Fatalf("missing argument did not show usage: %#v", log)
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
