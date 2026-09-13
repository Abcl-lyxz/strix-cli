package app

import (
	"encoding/json"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

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
