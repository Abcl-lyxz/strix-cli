package app

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	"github.com/muesli/termenv"
	"github.com/usestrix/strix/tui/internal/protocol"
)

func TestWorkspaceSelectionRemainsVisibleAcrossPageBoundary(t *testing.T) {
	model := inputModel(t)
	model.width, model.height = 100, 20
	model.modal = modalWorkspace
	model.dialog = workspaceDialog{Kind: "models", Title: "Models"}
	for i := range 30 {
		model.dialog.Rows = append(model.dialog.Rows, map[string]any{"label": fmt.Sprintf("model-%02d", i)})
	}

	for index := range model.dialog.Rows {
		model.dialog.Index = index
		view := ansi.Strip(model.workspaceView())
		want := fmt.Sprintf("› model-%02d", index)
		if !strings.Contains(view, want) {
			t.Fatalf("selection %d is outside the rendered window:\n%s", index, view)
		}
	}
}

func TestWorkspaceSelectionUsesSubtleRowHighlight(t *testing.T) {
	profile := lipgloss.ColorProfile()
	lipgloss.SetColorProfile(termenv.TrueColor)
	defer lipgloss.SetColorProfile(profile)

	model := inputModel(t)
	model.width, model.height = 100, 20
	model.modal = modalWorkspace
	model.dialog = workspaceDialog{Kind: "models", Title: "Models", Rows: []map[string]any{{"label": "model-a"}}}

	view := model.workspaceView()
	if !strings.Contains(view, "\x1b[48;2;") {
		t.Fatalf("selected row has no background highlight: %q", view)
	}
	if !strings.Contains(ansi.Strip(view), "› model-a") {
		t.Fatalf("selected row marker is missing:\n%s", ansi.Strip(view))
	}
}

func TestWorkspaceCommandErrorStaysInsideModal(t *testing.T) {
	model := inputModel(t)
	model.client = newClient(&recordingConn{})
	model.modal = modalWorkspace
	model.dialog = workspaceDialog{Kind: "form", Title: "Connect"}
	model.snapshot.SetupMode = true
	requestID := "failed-provider"
	model.client.pending[requestID] = "providers.connect"
	model.client.pendingByKey["providers.connect"] = requestID
	model.client.requestKeyByID[requestID] = "providers.connect"
	payload, err := json.Marshal(protocol.CommandResult{
		OK:      false,
		Command: "providers.connect",
		Error:   &protocol.CommandError{Message: "provider rejected the credential"},
	})
	if err != nil {
		t.Fatal(err)
	}

	model.handleEnvelope(protocol.Envelope{
		Version: protocol.Version, Type: "command_result", RequestID: requestID, Payload: payload,
	})

	if model.dialog.Error != "provider rejected the credential" {
		t.Fatalf("modal error = %q", model.dialog.Error)
	}
	if len(model.setupLog) != 0 || model.errorText != "" {
		t.Fatalf("modal error leaked: setup=%#v status=%q", model.setupLog, model.errorText)
	}
	model.closeModal()
	if model.dialog.Error != "" {
		t.Fatalf("closing modal retained error %q", model.dialog.Error)
	}
}

func TestProviderPickerKeepsConnectionsAndUsesProviderNativeForm(t *testing.T) {
	rows := providerWorkspaceRows(map[string]any{
		"connections": []any{map[string]any{
			"id": "custom", "provider_id": "custom", "name": "First gateway",
		}},
		"providers": []any{map[string]any{
			"id": "custom", "name": "Custom OpenAI-compatible", "auth_methods": []any{"api_key"},
		}},
	})
	if len(rows) != 2 || rows[0]["_kind"] != "connection" || rows[1]["_kind"] != "provider" {
		t.Fatalf("provider rows = %#v", rows)
	}

	model := inputModel(t)
	model.modal = modalWorkspace
	model.dialog = workspaceDialog{Kind: "providers", Title: "Providers", Rows: rows, Index: 1}
	updated, command := model.updateWorkspace(tea.KeyMsg{Type: tea.KeyEnter})
	model = updated.(Model)
	if command != nil || model.dialog.Kind != "form" {
		t.Fatalf("provider form did not open: kind=%q", model.dialog.Kind)
	}
	if len(model.dialog.Fields) < 2 || model.dialog.Fields[0].Key != "name" ||
		model.dialog.Fields[0].Input.Value() != "Custom OpenAI-compatible" ||
		model.dialog.Fields[1].Key != "auth_method" {
		t.Fatalf("provider form fields = %#v", model.dialog.Fields)
	}
}

func TestConnectedProviderOpensActionMenuThenItsModels(t *testing.T) {
	connection := &recordingConn{}
	model := inputModel(t)
	model.client = newClient(connection)
	model.modal = modalWorkspace
	model.dialog = workspaceDialog{Kind: "providers", Rows: []map[string]any{{
		"_kind": "connection", "id": "gateway", "name": "Gateway",
	}}}

	updated, command := model.updateWorkspace(tea.KeyMsg{Type: tea.KeyEnter})
	model = updated.(Model)
	if command != nil || model.dialog.Kind != "provider_actions" || len(model.dialog.Rows) != 3 {
		t.Fatalf("provider action menu did not open: %#v", model.dialog)
	}

	_, command = model.updateWorkspace(tea.KeyMsg{Type: tea.KeyEnter})
	envelope := commandFromCmd(t, command, connection)
	var payload map[string]any
	if err := json.Unmarshal(envelope.Payload, &payload); err != nil {
		t.Fatal(err)
	}
	if envelope.Type != "models.discover" || payload["connection_id"] != "gateway" {
		t.Fatalf("wrong model discovery: %#v", payload)
	}
}

func TestProviderDisconnectIsAVisibleActionAndControlChordNeverPollutesSearch(t *testing.T) {
	connection := &recordingConn{}
	model := inputModel(t)
	model.client = newClient(connection)
	model.modal = modalWorkspace
	model.dialog = workspaceDialog{Kind: "providers", Rows: []map[string]any{{
		"_kind": "connection", "id": "gateway", "name": "Gateway",
	}}}

	updated, command := model.updateWorkspace(tea.KeyMsg{Type: tea.KeyCtrlD})
	model = updated.(Model)
	if command != nil || model.dialog.Kind != "provider_actions" || model.dialog.Index != 2 {
		t.Fatalf("Ctrl+D did not open the visible disconnect action: %#v", model.dialog)
	}
	if model.dialog.Filter != "" {
		t.Fatalf("control chord leaked into search: %q", model.dialog.Filter)
	}

	_, command = model.updateWorkspace(tea.KeyMsg{Type: tea.KeyEnter})
	envelope := commandFromCmd(t, command, connection)
	var payload map[string]any
	if err := json.Unmarshal(envelope.Payload, &payload); err != nil {
		t.Fatal(err)
	}
	if envelope.Type != "providers.disconnect" || payload["connection_id"] != "gateway" {
		t.Fatalf("wrong disconnect command: %#v", payload)
	}
}

func TestComposerFooterKeepsBorderConnectedAndColorsOnlyTheHintAsText(t *testing.T) {
	footer := composerFooter(72, green)
	plain := ansi.Strip(footer)
	if ansi.StringWidth(plain) != 72 || !strings.HasPrefix(plain, "╰─ ") || !strings.HasSuffix(plain, "╯") {
		t.Fatalf("composer footer is not a complete 72-cell border: %q", plain)
	}
	if !strings.Contains(plain, "[Ctrl+S Send]") || !strings.Contains(plain, "──╯") {
		t.Fatalf("composer footer lost its hint or closing rule: %q", plain)
	}
}

func TestProviderConnectResultRefreshesTheOpenPicker(t *testing.T) {
	model := inputModel(t)
	model.client = newClient(&recordingConn{})
	model.modal = modalWorkspace
	model.dialog = workspaceDialog{Kind: "form", Title: "Connect custom"}

	command, handled := model.workspaceResult(protocol.CommandResult{
		OK: true, Command: "providers.connect", Result: json.RawMessage(`{"saved":true}`),
	})

	if !handled || command == nil {
		t.Fatal("provider result did not schedule a refresh")
	}
	if model.modal != modalWorkspace || model.dialog.Kind != "providers" || model.dialog.Command != "providers.list" {
		t.Fatalf("provider picker was not retained: modal=%v dialog=%#v", model.modal, model.dialog)
	}
	if _, ok := command().(tea.BatchMsg); !ok {
		t.Fatal("provider result did not batch the toast and list refresh")
	}
}

func TestInboxCanInvokeSecondIncidentAction(t *testing.T) {
	connection := &recordingConn{}
	model := inputModel(t)
	model.client = newClient(connection)
	model.modal = modalWorkspace
	model.dialog = workspaceDialog{Kind: "notifications", Rows: []map[string]any{{
		"id": "incident", "title": "Provider required", "actions": []any{
			map[string]any{"label": "Configure provider", "kind": "open_routes"},
			map[string]any{"label": "Retry connection", "kind": "retry_route_test"},
		},
	}}}
	updated, _ := model.updateWorkspace(tea.KeyMsg{Type: tea.KeyCtrlA})
	model = updated.(Model)
	if model.dialog.Kind != "notification_actions" || len(model.dialog.Rows) != 2 {
		t.Fatal("notification actions were not offered in a picker")
	}
	updated, _ = model.updateWorkspace(tea.KeyMsg{Type: tea.KeyDown})
	model = updated.(Model)
	_, command := model.updateWorkspace(tea.KeyMsg{Type: tea.KeyEnter})
	envelope := commandFromCmd(t, command, connection)
	var payload map[string]any
	if err := json.Unmarshal(envelope.Payload, &payload); err != nil {
		t.Fatal(err)
	}
	if envelope.Type != "notifications.manage" || payload["id"] != "incident" || payload["index"] != float64(1) {
		t.Fatalf("wrong incident action: %#v", payload)
	}
}

func TestInboxSearchDoesNotDismissWhenTypingD(t *testing.T) {
	model := inputModel(t)
	model.modal = modalWorkspace
	model.dialog = workspaceDialog{Kind: "notifications", Rows: []map[string]any{{"id": "incident"}}}
	updated, command := model.updateWorkspace(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'d'}})
	if command != nil || updated.(Model).dialog.Filter != "d" {
		t.Fatal("typing in the inbox filter triggered an incident action")
	}
}
