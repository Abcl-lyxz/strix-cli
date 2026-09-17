package app

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/usestrix/strix/tui/internal/protocol"
)

type formField struct {
	Key, Label, Kind string
	Input            textinput.Model
}
type workspaceDialog struct {
	Kind, Title, Error, Filter, Command string
	Rows                                []map[string]any
	Fields                              []formField
	Index                               int
	Payload                             map[string]any
	Persist                             bool
}
type editorResult struct {
	Text string
	Err  error
}

func (m Model) sendComposer() (tea.Model, tea.Cmd) {
	value := m.input.Value()
	if strings.TrimSpace(value) == "" {
		return m, nil
	}
	if len([]byte(value)) > maxPromptBytes {
		m.errorText = "Prompt exceeds 256 KiB; shorten it or attach a file"
		return m, nil
	}
	if len(m.pendingDrafts) > 0 || len(m.outboundDrafts) > 0 {
		cmd := m.showToast("Waiting for message acknowledgement")
		return m, cmd
	}
	m.draftHistory = append(m.draftHistory, value)
	if len(m.draftHistory) > 50 {
		m.draftHistory = m.draftHistory[1:]
	}
	m.draftIndex = len(m.draftHistory)
	m.input.SetValue("")
	m.resizeViewport()
	pasted := m.pastedDraft
	m.pastedDraft = false
	if pasted || strings.Contains(value, "\n") {
		if m.snapshot.SetupMode {
			return m.submitSetupPrompt(value)
		}
		if len(m.snapshot.Agents) == 0 {
			m.restoreDraft(value)
			return m, nil
		}
		m.rememberDraft("agent.send_message", value)
		return m, sendWithDraft(m.client, "agent.send_message", map[string]any{"agent_id": m.snapshot.Agents[m.selectedAgent].ID, "message": value}, value)
	}
	return m.submit(value)
}

func (m *Model) openWorkspace(kind, title, command string) tea.Cmd {
	m.modal = modalWorkspace
	m.dialog = workspaceDialog{Kind: kind, Title: title, Command: command, Payload: map[string]any{}}
	m.input.Blur()
	if command != "" {
		return send(m.client, command, map[string]any{})
	}
	return nil
}

func inputField(key, label, kind string, value any) formField {
	field := textinput.New()
	field.CharLimit = 32768
	field.Width = 46
	if value != nil {
		field.SetValue(fmt.Sprint(value))
	}
	if kind == "secret" {
		field.EchoMode = textinput.EchoPassword
		field.EchoCharacter = '•'
	}
	return formField{key, label, kind, field}
}

func (m *Model) openForm(title, command string, payload map[string]any, fields ...formField) {
	m.modal = modalWorkspace
	m.dialog = workspaceDialog{Kind: "form", Title: title, Command: command, Payload: payload, Fields: fields}
	m.input.Blur()
	if len(fields) > 0 {
		m.dialog.Fields[0].Input.Focus()
	}
}

func decodedRows(data map[string]any, key string) []map[string]any {
	rows := []map[string]any{}
	if values, ok := data[key].([]any); ok {
		for _, value := range values {
			if row, ok := value.(map[string]any); ok {
				copy := make(map[string]any, len(row)+3)
				for field, item := range row {
					copy[field] = item
				}
				rows = append(rows, copy)
			}
		}
	}
	return rows
}

func providerWorkspaceRows(data map[string]any) []map[string]any {
	rows := []map[string]any{}
	for _, row := range decodedRows(data, "connections") {
		row["_kind"] = "connection"
		row["section"] = "Connected"
		row["label"] = fmt.Sprintf("%v · %v · connected", row["name"], row["provider_id"])
		rows = append(rows, row)
	}
	for _, row := range decodedRows(data, "providers") {
		row["_kind"] = "provider"
		row["section"] = "Add provider"
		rows = append(rows, row)
	}
	return rows
}

func modelWorkspaceRows(data map[string]any) []map[string]any {
	rows := []map[string]any{}
	connectionNames := map[string]string{}
	for _, row := range decodedRows(data, "connections") {
		id := fmt.Sprint(row["id"])
		name := fmt.Sprint(row["name"])
		connectionNames[id] = name
		row["_kind"] = "connection"
		row["section"] = "Discover / refresh"
		row["label"] = fmt.Sprintf("%s · %v", name, row["provider_id"])
		rows = append(rows, row)
	}
	for _, row := range decodedRows(data, "models") {
		row["_kind"] = "model"
		connectionID := fmt.Sprint(row["connection_id"])
		section := connectionNames[connectionID]
		if section == "" {
			section = connectionID
		}
		row["section"] = "Models · " + section
		state := "off"
		if enabled, _ := row["enabled"].(bool); enabled {
			state = "on"
		}
		tier := fmt.Sprint(row["quality_tier"])
		if tier == "" || tier == "<nil>" {
			tier = "unknown"
		}
		row["label"] = fmt.Sprintf("[%s] %v · %s", state, row["model_id"], tier)
		rows = append(rows, row)
	}
	return rows
}

func workspaceRowIdentity(row map[string]any) string {
	return fmt.Sprint(row["_kind"]) + "\x00" + fmt.Sprint(row["id"])
}

func (m Model) selectedWorkspaceIdentity() string {
	rows := m.filteredWorkspaceRows()
	if len(rows) == 0 {
		return ""
	}
	return workspaceRowIdentity(rows[min(m.dialog.Index, len(rows)-1)])
}

func (m *Model) restoreWorkspaceSelection(identity string) {
	m.dialog.Index = 0
	if identity == "" {
		return
	}
	for index, row := range m.filteredWorkspaceRows() {
		if workspaceRowIdentity(row) == identity {
			m.dialog.Index = index
			return
		}
	}
}

func (m *Model) workspaceResult(result protocol.CommandResult) (tea.Cmd, bool) {
	switch result.Command {
	case "settings.list", "providers.list", "models.list", "models.discover", "router.status", "sessions.list", "attachments.list", "paths.complete":
		var data map[string]any
		if err := json.Unmarshal(result.Result, &data); err != nil {
			m.dialog.Error = err.Error()
			return nil, true
		}
		identity := m.selectedWorkspaceIdentity()
		m.dialog.Error = ""
		switch result.Command {
		case "providers.list":
			m.dialog.Rows = providerWorkspaceRows(data)
		case "models.list", "models.discover":
			m.dialog.Rows = modelWorkspaceRows(data)
			m.dialog.Kind = "models"
		default:
			key := map[string]string{"settings.list": "fields", "router.status": "routes", "sessions.list": "runs", "attachments.list": "attachments", "paths.complete": "paths"}[result.Command]
			m.dialog.Rows = decodedRows(data, key)
		}
		m.restoreWorkspaceSelection(identity)
		if e, ok := data["error"].(string); ok {
			m.dialog.Error = e
		}
		return nil, true
	case "notifications.manage":
		if m.modal != modalWorkspace || m.dialog.Kind != "notifications" {
			return nil, false
		}
		var data map[string]any
		_ = json.Unmarshal(result.Result, &data)
		if action, ok := data["action"].(string); ok {
			target, _ := data["target"].(string)
			switch action {
			case "open_agent":
				for i, a := range m.snapshot.Agents {
					if a.ID == target {
						m.selectedAgent = i
						m.closeModal()
						m.refreshViewport()
					}
				}
			case "open_finding":
				for i, v := range m.snapshot.Vulnerabilities {
					if fmt.Sprint(v["id"]) == target {
						m.selectedVuln = i
						m.openModal(modalVulnerability)
					}
				}
			case "open_routes":
				return m.openWorkspace("providers", "Providers", "providers.list"), true
			case "retry_route_test":
				return send(m.client, "providers.test", map[string]any{}), true
			case "start_update":
				m.closeModal()
				return send(m.client, "update.start", map[string]any{}), true
			case "dismiss":
				return send(m.client, "notifications.manage", map[string]any{"operation": "dismiss", "id": target}), true
			default:
				m.dialog.Error = "Use /update to run an explicit application update"
			}
			return nil, true
		}
		if unread, ok := data["unread"].(float64); ok {
			m.snapshot.NotificationUnread = int(unread)
		}
		m.dialog.Rows = nil
		if rows, ok := data["notifications"].([]any); ok {
			for _, r := range rows {
				if row, ok := r.(map[string]any); ok {
					m.dialog.Rows = append(m.dialog.Rows, row)
				}
			}
		}
		m.dialog.Index = min(m.dialog.Index, max(0, len(m.dialog.Rows)-1))
		return nil, true
	case "providers.connect", "providers.disconnect":
		if m.modal != modalWorkspace {
			return m.showToast("Provider connections updated"), true
		}
		m.dialog = workspaceDialog{Kind: "providers", Title: "Providers", Command: "providers.list", Payload: map[string]any{}}
		m.dialog.Error = ""
		return tea.Batch(m.showToast("Provider connections updated"), send(m.client, "providers.list", map[string]any{})), true
	case "models.toggle":
		if m.modal != modalWorkspace {
			return m.showToast("Model availability updated"), true
		}
		m.dialog.Kind = "models"
		m.dialog.Title = "Models"
		m.dialog.Error = ""
		return tea.Batch(m.showToast("Model availability updated"), send(m.client, "models.list", map[string]any{})), true
	case "mcp.update", "notifications.preferences", "settings.update", "providers.test", "attachments.add", "attachments.remove", "scan.new", "scan.resume":
		m.closeModal()
		return m.showToast("Updated successfully"), true
	case "update.start", "doctor.run":
		var data map[string]any
		_ = json.Unmarshal(result.Result, &data)
		message := fmt.Sprint(data["message"])
		if message == "<nil>" || message == "" {
			message = "Completed"
		}
		return m.showToast(message), true
	}
	return nil, false
}

func rowLabel(row map[string]any) string {
	for _, key := range []string{"label", "title", "name", "run_name", "run_id", "path", "id"} {
		if value, ok := row[key].(string); ok && value != "" {
			return value
		}
	}
	return "Item"
}

func (m Model) filteredWorkspaceRows() []map[string]any {
	rows := []map[string]any{}
	for _, row := range m.dialog.Rows {
		data, _ := json.Marshal(row)
		if strings.Contains(strings.ToLower(string(data)), strings.ToLower(m.dialog.Filter)) {
			rows = append(rows, row)
		}
	}
	return rows
}

func (m Model) workspaceView() string {
	width := max(16, min(78, m.width-6))
	height := max(3, m.height-12)
	lines := []string{lipgloss.NewStyle().Bold(true).Foreground(green).Render(m.dialog.Title), ""}
	if m.dialog.Kind == "form" {
		slots := max(1, (height-3)/2)
		start := max(0, m.dialog.Index-slots+1)
		for i := start; i < min(len(m.dialog.Fields), start+slots); i++ {
			f := m.dialog.Fields[i]
			marker := "  "
			if i == m.dialog.Index {
				marker = "› "
			}
			f.Input.Width = max(10, width-6)
			lines = append(lines, marker+f.Label, f.Input.View())
		}
		lines = append(lines, "", "Tab next · Ctrl+S apply · Esc cancel")
	} else {
		lines = append(lines, "Search: "+m.dialog.Filter)
		rows := m.filteredWorkspaceRows()
		slots := max(1, height-5)
		start := max(0, m.dialog.Index-slots+1)
		for i := start; i < min(len(rows), start+slots); i++ {
			marker := "  "
			if i == m.dialog.Index {
				marker = "› "
			}
			label := rowLabel(rows[i])
			if section, ok := rows[i]["section"].(string); ok {
				label = section + " / " + label
			}
			lines = append(lines, marker+label)
		}
		if len(rows) == 0 {
			lines = append(lines, "No items. Press Esc to return.")
		}
		if m.dialog.Kind == "notifications" && len(rows) > 0 {
			row := rows[min(m.dialog.Index, len(rows)-1)]
			lines = append(lines, "", fmt.Sprint(row["detail"]), "Ctrl+R read · Ctrl+D dismiss · Ctrl+A action · Ctrl+X clear read")
		}
		footer := "↑↓ select · Enter open · type to filter · Esc back"
		switch m.dialog.Kind {
		case "providers":
			footer = "↑↓ select · Enter connect/open models · Ctrl+D disconnect · type to filter · Esc back"
		case "models":
			footer = "↑↓ select · Enter refresh/toggle · type to filter · Esc back"
		}
		lines = append(lines, "", footer)
	}
	if m.dialog.Error != "" {
		lines = append(lines, lipgloss.NewStyle().Foreground(red).Render(m.dialog.Error))
	}
	content := strings.Join(lines, "\n")
	return lipgloss.NewStyle().Width(width).MaxHeight(max(5, m.height-2)).Padding(1, 2).Border(lipgloss.RoundedBorder()).BorderForeground(green).Render(content)
}

func (m Model) updateWorkspace(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	if key.String() == "esc" {
		if m.dialog.Kind == "models" && len(m.dialog.Fields) > 0 {
			m.dialog.Kind = "form"
			m.dialog.Index = 0
			return m, m.dialog.Fields[0].Input.Focus()
		}
		m.closeModal()
		return m, nil
	}
	if m.dialog.Kind == "form" {
		switch key.String() {
		case "tab", "shift+tab":
			if len(m.dialog.Fields) == 0 {
				return m, nil
			}
			m.dialog.Fields[m.dialog.Index].Input.Blur()
			delta := 1
			if key.String() == "shift+tab" {
				delta = -1
			}
			m.dialog.Index = clampCycle(m.dialog.Index+delta, len(m.dialog.Fields))
			return m, m.dialog.Fields[m.dialog.Index].Input.Focus()
		case "ctrl+s":
			payload := map[string]any{}
			for k, v := range m.dialog.Payload {
				payload[k] = v
			}
			for _, f := range m.dialog.Fields {
				var value any = f.Input.Value()
				switch f.Kind {
				case "number":
					if f.Input.Value() == "" {
						value = nil
						break
					}
					n, err := strconv.ParseFloat(f.Input.Value(), 64)
					if err != nil {
						m.dialog.Error = "Enter a number"
						return m, nil
					}
					value = n
				case "boolean":
					b, ok := parseToggle(f.Input.Value())
					if !ok {
						m.dialog.Error = "Enter true or false"
						return m, nil
					}
					value = b
				}
				payload[f.Key] = value
			}
			return m, send(m.client, m.dialog.Command, payload)
		}
		if len(m.dialog.Fields) > 0 {
			var cmd tea.Cmd
			m.dialog.Fields[m.dialog.Index].Input, cmd = m.dialog.Fields[m.dialog.Index].Input.Update(key)
			return m, cmd
		}
		return m, nil
	}
	rows := m.filteredWorkspaceRows()
	switch key.String() {
	case "up":
		m.dialog.Index = max(0, m.dialog.Index-1)
	case "down":
		m.dialog.Index = min(max(0, len(rows)-1), m.dialog.Index+1)
	case "backspace":
		r := []rune(m.dialog.Filter)
		if len(r) > 0 {
			m.dialog.Filter = string(r[:len(r)-1])
		}
		m.dialog.Index = 0
	case "ctrl+r", "ctrl+d", "ctrl+a", "ctrl+x":
		if m.dialog.Kind == "notifications" && len(rows) > 0 {
			operation := map[string]string{"ctrl+r": "read", "ctrl+d": "dismiss", "ctrl+a": "action", "ctrl+x": "clear"}[key.String()]
			if operation == "action" {
				row := rows[min(m.dialog.Index, len(rows)-1)]
				actions, _ := row["actions"].([]any)
				if len(actions) == 0 {
					m.dialog.Error = "This notification has no actions"
					return m, nil
				}
				m.dialog = workspaceDialog{Kind: "notification_actions", Title: "Notification actions", Payload: map[string]any{"id": row["id"]}}
				for index, action := range actions {
					if value, ok := action.(map[string]any); ok {
						m.dialog.Rows = append(m.dialog.Rows, map[string]any{"label": value["label"], "index": index})
					}
				}
				return m, nil
			}
			return m, send(m.client, "notifications.manage", map[string]any{"operation": operation, "id": rows[m.dialog.Index]["id"]})
		}
		if key.String() == "ctrl+d" && m.dialog.Kind == "providers" && len(rows) > 0 {
			row := rows[min(m.dialog.Index, len(rows)-1)]
			if fmt.Sprint(row["_kind"]) != "connection" {
				m.dialog.Error = "Select a connected provider to disconnect it"
				return m, nil
			}
			return m, send(m.client, "providers.disconnect", map[string]any{"connection_id": row["id"]})
		}
		m.dialog.Filter += key.String()
		m.dialog.Index = 0
	case "enter":
		if len(rows) == 0 {
			return m, nil
		}
		row := rows[min(m.dialog.Index, len(rows)-1)]
		switch m.dialog.Kind {
		case "notification_actions":
			payload := map[string]any{"operation": "action", "id": m.dialog.Payload["id"], "index": row["index"]}
			m.dialog.Kind = "notifications"
			return m, send(m.client, "notifications.manage", payload)
		case "router":
			m.dialog.Error = fmt.Sprintf("%v · %v", row["model"], row["health"])
		case "commands":
			m.closeModal()
			return m.submit(fmt.Sprint(row["name"]))
		case "settings":
			kind := fmt.Sprint(row["type"])
			if row["secret"] == true {
				kind = "secret"
			}
			m.openForm(rowLabel(row)+" · "+fmt.Sprint(row["source"])+" · "+fmt.Sprint(row["apply"]), "settings.update", map[string]any{"id": row["id"]}, inputField("value", rowLabel(row), kind, row["value"]))
		case "providers":
			if fmt.Sprint(row["_kind"]) == "connection" {
				m.dialog = workspaceDialog{Kind: "models", Title: "Models", Command: "models.discover", Payload: map[string]any{"connection_id": row["id"]}}
				return m, send(m.client, "models.discover", map[string]any{"connection_id": row["id"]})
			}
			providerID := fmt.Sprint(row["id"])
			fields := []formField{
				inputField("name", "Display name", "text", rowLabel(row)),
			}
			if methods, ok := row["auth_methods"].([]any); ok && len(methods) > 0 {
				fields = append(fields, inputField("auth_method", "Authentication method", "text", methods[0]))
			}
			if specs, ok := row["fields"].([]any); ok {
				for _, raw := range specs {
					if spec, ok := raw.(map[string]any); ok {
						kind := fmt.Sprint(spec["kind"])
						if kind == "choice" {
							kind = "text"
						}
						fields = append(fields, inputField(fmt.Sprint(spec["id"]), fmt.Sprint(spec["label"]), kind, ""))
					}
				}
			}
			m.openForm("Connect "+rowLabel(row), "providers.connect", map[string]any{"provider_id": providerID}, fields...)
		case "models":
			if fmt.Sprint(row["_kind"]) == "connection" {
				return m, send(m.client, "models.discover", map[string]any{"connection_id": row["id"], "refresh": true})
			}
			enabled, _ := row["enabled"].(bool)
			return m, send(m.client, "models.toggle", map[string]any{"model_id": row["id"], "enabled": !enabled})
		case "sessions":
			return m, send(m.client, "scan.resume", map[string]any{"run": row["name"]})
		case "paths":
			m.openForm("Attach "+rowLabel(row), "attachments.add", map[string]any{}, inputField("path", "Local path", "text", row["path"]), inputField("role", "Role: context or target", "text", "context"))
		case "notifications":
			return m, send(m.client, "notifications.manage", map[string]any{"operation": "read", "id": row["id"]})
		}
	default:
		if key.Type == tea.KeyRunes {
			m.dialog.Filter += string(key.Runes)
			m.dialog.Index = 0
		}
	}
	return m, nil
}

func (m Model) externalEditor() tea.Cmd {
	file, err := os.CreateTemp("", "strix-prompt-*.md")
	if err != nil {
		return func() tea.Msg { return editorResult{Err: err} }
	}
	path := file.Name()
	_, err = file.WriteString(m.input.Value())
	_ = file.Close()
	if err != nil {
		_ = os.Remove(path)
		return func() tea.Msg { return editorResult{Err: err} }
	}
	editor := m.snapshot.EditorCommand
	if editor == "" {
		editor = os.Getenv("VISUAL")
	}
	if editor == "" {
		editor = os.Getenv("EDITOR")
	}
	if editor == "" {
		editor = "notepad"
		if os.PathSeparator != '\\' {
			editor = "vi"
		}
	}
	// No shell expansion: an editor command is an executable plus arguments.
	parts := strings.Fields(editor)
	if strings.HasPrefix(editor, "\"") {
		if end := strings.Index(editor[1:], "\""); end >= 0 {
			parts = append([]string{editor[1 : end+1]}, strings.Fields(editor[end+2:])...)
		}
	} else if info, err := os.Stat(editor); err == nil && !info.IsDir() {
		parts = []string{editor}
	}
	if len(parts) == 0 {
		_ = os.Remove(path)
		return func() tea.Msg { return editorResult{Err: fmt.Errorf("set VISUAL or EDITOR to an executable")} }
	}
	command := exec.Command(parts[0], append(parts[1:], path)...)
	return tea.ExecProcess(command, func(err error) tea.Msg {
		defer os.Remove(path)
		if err != nil {
			return editorResult{Err: err}
		}
		data, err := os.ReadFile(path)
		if len(data) > maxPromptBytes {
			return editorResult{Err: fmt.Errorf("editor content exceeds 256 KiB")}
		}
		return editorResult{Text: string(data), Err: err}
	})
}
