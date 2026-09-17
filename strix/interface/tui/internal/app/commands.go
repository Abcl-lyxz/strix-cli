package app

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/usestrix/strix/tui/internal/render"
)

type slashCommand struct {
	name        string
	args        string
	description string
}

// slashCommands is deliberately ordered around the most common workflow.
// The launch palette shows a short prefix of this list; F1 shows the complete
// reference. Commands that mutate setup are rejected after the scan starts.
var slashCommands = []slashCommand{
	{"connect", "", "connect or disconnect a provider"},
	{"models", "", "discover and enable provider models"},
	{"router", "", "inspect automatic routing decisions and health"},
	{"settings", "", "edit typed application and scan settings"},
	{"targets", "[add|remove|clear]", "manage scan targets"},
	{"attach", "[path]", "attach a local file or folder"},
	{"mcp", "", "configure MCP connections for the next scan"},
	{"sessions", "", "browse and resume local runs"},
	{"notifications", "[unread|read <id>|dismiss <id>|clear]", "open the notification inbox"},
	{"update", "", "check and install a verified update"},
	{"doctor", "", "run installation and provider diagnostics"},
	{"start", "", "launch with the current setup"},
	{"status", "", "show model, router, and run status"},
	{"agents", "[stop <id>]", "focus or stop live agents"},
	{"findings", "", "focus the findings panel"},
	{"trace", "", "focus the agent trace"},
	{"viewer", "", "open the read-only live report viewer"},
	{"find", "<text>", "search local workspace without an AI turn"},
	{"editor", "", "compose in your external editor"},
	{"new", "", "start a new session"},
	{"help", "", "show every command and shortcut"},
	{"quit", "", "quit Strix"},
}

var removedSlashCommands = map[string]bool{
	"model": true, "apikey": true, "baseurl": true, "routes": true, "routing": true,
	"config": true, "retry": true, "target": true, "untarget": true, "mode": true,
	"budget": true, "turns": true, "scope": true, "diff-base": true, "streaming": true,
	"cache": true, "timeout": true, "toolcalls": true, "images": true, "agent": true,
	"stop": true, "follow": true, "clear": true, "notify-settings": true,
}

func slashParts(value string) (name, argument string, ok bool) {
	value = strings.TrimSpace(value)
	if !strings.HasPrefix(value, "/") {
		return "", "", false
	}
	body := strings.TrimPrefix(value, "/")
	if body == "" || body == "?" {
		return "help", "", true
	}
	if split := strings.IndexAny(body, " \t\r\n"); split >= 0 {
		name, argument = body[:split], strings.TrimSpace(body[split+1:])
	} else {
		name = body
	}
	name = strings.ToLower(name)
	for _, command := range slashCommands {
		if command.name == name {
			return name, argument, true
		}
	}
	if removedSlashCommands[name] {
		return "_removed", name, true
	}
	for _, command := range slashCommands {
		if strings.HasPrefix(command.name, name) {
			return "_partial", name, true
		}
	}
	// Absolute paths are valid scan prompts, so unknown slash-prefixed text is
	// ordinary input rather than an "unknown command" failure.
	return "", "", false
}

func (m Model) slashCandidates() []slashCommand {
	value := strings.TrimSpace(m.input.Value())
	if !strings.HasPrefix(value, "/") || strings.Contains(value, "\n") {
		return nil
	}
	prefix := strings.ToLower(strings.TrimPrefix(value, "/"))
	if split := strings.IndexAny(prefix, " \t"); split >= 0 {
		prefix = prefix[:split]
	}
	var matches []slashCommand
	for _, command := range slashCommands {
		if strings.HasPrefix(command.name, prefix) {
			matches = append(matches, command)
		}
	}
	return matches
}

func (m Model) commandPaletteView(width int) string {
	matches := m.slashCandidates()
	if len(matches) == 0 {
		return ""
	}
	limit := 7
	compact := m.height > 0 && m.height < 20
	if compact {
		limit = 2
	} else if m.height > 0 && m.height < 24 {
		limit = 3
	}
	matches = matches[:min(limit, len(matches))]
	inner := max(10, width-4)
	rows := []string{render.Bold(green).Render("Commands") + render.Dim().Render("  tab completes")}
	for _, command := range matches {
		usage := "/" + command.name
		if command.args != "" {
			usage += " " + command.args
		}
		left := render.Col(white).Render(usage)
		gap := max(2, 28-lipgloss.Width(usage))
		row := left + strings.Repeat(" ", gap) + render.Dim().Render(command.description)
		rows = append(rows, truncate(row, inner))
	}
	if hidden := len(m.slashCandidates()) - len(matches); hidden > 0 && !compact {
		rows = append(rows, render.Dim().Render(fmt.Sprintf("… %d more · F1 for all", hidden)))
	}
	return lipgloss.NewStyle().Width(max(1, width-2)).Padding(0, 1).
		Border(lipgloss.RoundedBorder()).BorderForeground(dark).
		Render(strings.Join(rows, "\n"))
}

func (m *Model) completeSlashCommand() bool {
	matches := m.slashCandidates()
	if len(matches) == 0 {
		return false
	}
	m.input.SetValue("/" + matches[0].name + " ")
	m.input.CursorEnd()
	m.resizeViewport()
	return true
}

func (m Model) inputView() string {
	return m.input.View()
}

func (m *Model) slashError(message string) tea.Cmd {
	if m.snapshot.SetupMode {
		m.setupMsg(message, render.Col(red))
		m.resizeViewport()
		return nil
	}
	return m.showToastFor(message, 5*time.Second)
}

func (m *Model) slashInfo(message string) tea.Cmd {
	if m.snapshot.SetupMode {
		m.setupMsg(message, render.Dim())
		m.resizeViewport()
		return nil
	}
	return m.showToastFor(message, 5*time.Second)
}

func (m *Model) requireSetup(command string) tea.Cmd {
	if m.snapshot.SetupMode {
		return nil
	}
	return m.slashError("/" + command + " is available before a scan starts")
}

func requiredArgument(m *Model, command, argument, usage string) (string, tea.Cmd, bool) {
	if strings.TrimSpace(argument) != "" {
		return strings.TrimSpace(argument), nil, true
	}
	return "", m.slashError("Usage: /" + command + " " + usage), false
}

func parseToggle(argument string) (bool, bool) {
	switch strings.ToLower(strings.TrimSpace(argument)) {
	case "on", "true", "yes", "1":
		return true, true
	case "off", "false", "no", "0":
		return false, true
	default:
		return false, false
	}
}

func (m Model) submitSlashCommand(value string) (tea.Model, tea.Cmd, bool) {
	name, argument, known := slashParts(value)
	if !known {
		return m, nil, false
	}
	if name == "_removed" {
		return m, m.slashError("/" + argument + " was removed in Strix v2; use /help for the canonical workflow"), true
	}
	if name == "_partial" {
		m.input.SetValue("/" + argument)
		m.input.CursorEnd()
		return m, m.slashError("Incomplete command; press Tab to complete it"), true
	}
	return m.submitCanonicalCommand(name, argument)
}

func (m Model) submitCanonicalCommand(name, argument string) (tea.Model, tea.Cmd, bool) { //nolint:gocyclo
	argument = strings.TrimSpace(argument)
	switch name {
	case "connect":
		return m, m.openWorkspace("providers", "Provider connections", "providers.list"), true
	case "models":
		return m, m.openWorkspace("models", "Models", "models.list"), true
	case "router":
		return m, m.openWorkspace("router", "Automatic router", "router.status"), true
	case "settings":
		return m, m.openWorkspace("settings", "Settings", "settings.list"), true
	case "targets":
		if argument == "" {
			if len(m.snapshot.Targets) == 0 {
				return m, m.slashInfo("No targets queued"), true
			}
			return m, m.slashInfo(fmt.Sprintf("%d target(s): %s", m.snapshot.TargetCount, strings.Join(m.snapshot.Targets, ", "))), true
		}
		parts := strings.SplitN(argument, " ", 2)
		action := strings.ToLower(parts[0])
		if action == "clear" && len(parts) == 1 {
			return m, send(m.client, "setup.clear_targets", map[string]any{}), true
		}
		if len(parts) != 2 || strings.TrimSpace(parts[1]) == "" {
			return m, m.slashError("Usage: /targets add <target> | remove <target> | clear"), true
		}
		if action == "add" {
			return m, send(m.client, "setup.add_target", map[string]any{"target": strings.TrimSpace(parts[1])}), true
		}
		if action == "remove" {
			return m, send(m.client, "setup.remove_target", map[string]any{"target": strings.TrimSpace(parts[1])}), true
		}
		return m, m.slashError("Usage: /targets add <target> | remove <target> | clear"), true
	case "attach":
		if argument == "" {
			m.openForm("Attach a file or folder", "attachments.add", map[string]any{}, inputField("path", "Local path", "text", ""), inputField("role", "Role: context or target", "text", "context"))
			return m, nil, true
		}
		return m, send(m.client, "attachments.add", map[string]any{"path": argument, "role": "context"}), true
	case "mcp":
		m.openForm("MCP connection · next scan", "mcp.update", map[string]any{}, inputField("name", "Name", "text", ""), inputField("transport", "Transport: http or stdio", "text", "http"), inputField("url", "HTTP endpoint", "text", ""), inputField("command", "Executable (stdio)", "text", ""), inputField("args", "Arguments (JSON array)", "text", "[]"), inputField("token", "Bearer token (optional)", "secret", ""))
		return m, nil, true
	case "sessions":
		return m, m.openWorkspace("sessions", "Local sessions", "sessions.list"), true
	case "notifications":
		payload, err := notificationCommandPayload(argument)
		if err != "" {
			return m, m.slashError(err), true
		}
		m.modal = modalWorkspace
		m.dialog = workspaceDialog{Kind: "notifications", Title: "Notifications", Command: "notifications.manage", Payload: payload}
		return m, send(m.client, "notifications.manage", payload), true
	case "update":
		return m, send(m.client, "update.start", map[string]any{}), true
	case "doctor":
		return m, send(m.client, "doctor.run", map[string]any{}), true
	case "start":
		if cmd := m.requireSetup(name); cmd != nil {
			return m, cmd, true
		}
		payload := map[string]any{}
		if len(m.snapshot.Targets) == 0 {
			m.pendingPrompt = m.snapshot.Instruction
			payload["mount_working_dir"] = true
		}
		return m, send(m.client, "setup.start", payload), true
	case "status":
		return m, send(m.client, "router.status", map[string]any{}), true
	case "agents":
		if strings.HasPrefix(strings.ToLower(argument), "stop ") {
			id := strings.TrimSpace(argument[len("stop "):])
			return m, send(m.client, "agent.stop", map[string]any{"agent_id": id}), true
		}
		m.focus = focusAgents
		m.input.Blur()
		return m, nil, true
	case "findings":
		if len(m.snapshot.Vulnerabilities) == 0 {
			return m, m.slashError("No findings yet"), true
		}
		m.focus = focusVulnerabilities
		m.input.Blur()
		return m, nil, true
	case "trace":
		m.focus = focusChat
		m.input.Blur()
		return m, nil, true
	case "viewer":
		return m, send(m.client, "viewer.open", map[string]any{}), true
	case "find":
		query, cmd, ok := requiredArgument(&m, name, argument, "<text>")
		if !ok {
			return m, cmd, true
		}
		return m, send(m.client, "workspace.find", map[string]any{"query": query}), true
	case "editor":
		return m, m.externalEditor(), true
	case "new":
		return m, send(m.client, "scan.new", map[string]any{}), true
	case "help":
		m.openModal(modalHelp)
		return m, nil, true
	case "quit":
		if m.snapshot.SetupMode {
			m.quitting = true
			return m, tea.Batch(send(m.client, "app.quit", map[string]any{}), tea.Quit), true
		}
		m.modalChoice = 1
		m.openModal(modalQuit)
		return m, nil, true
	}
	return m, m.slashError("Unknown command: /" + name), true
}

func (m Model) commandHelpView() string {
	width := min(76, max(44, m.width-4))
	inner := width - 4
	title := lipgloss.NewStyle().Bold(true).Foreground(green).Width(inner).Align(lipgloss.Center).Render("Strix Help · command palette")
	rows := make([]string, 0, len(slashCommands))
	for _, command := range slashCommands {
		usage := "/" + command.name
		if command.args != "" {
			usage += " " + command.args
		}
		gap := max(2, 31-lipgloss.Width(usage))
		rows = append(rows, render.Col(white).Render(usage)+strings.Repeat(" ", gap)+render.Dim().Render(command.description))
	}
	body := render.Bold(green).Render("Commands") + "\n" + strings.Join(rows, "\n") +
		"\n\n" + render.Bold(green).Render("Keys") + "\n" +
		render.Col(textColor).Render("F1 help · Tab complete/switch · Ctrl+J newline · Ctrl+O viewer\nEsc stop agent · Ctrl+Q quit · arrows navigate")
	footer := render.Dim().Render("Type / to search commands · press any key to close")
	content := title + "\n\n" + lipgloss.NewStyle().Width(inner).Render(body) + "\n\n" + footer
	return lipgloss.NewStyle().Width(width - 2).Border(lipgloss.RoundedBorder()).
		BorderForeground(green).Background(black).Padding(1).Render(content)
}

func notificationCommandPayload(argument string) (map[string]any, string) {
	parts := strings.Fields(argument)
	payload := map[string]any{"operation": "list"}
	if len(parts) == 0 || (len(parts) == 1 && strings.EqualFold(parts[0], "all")) {
		return payload, ""
	}
	switch strings.ToLower(parts[0]) {
	case "unread":
		if len(parts) != 1 {
			return nil, "Usage: /notifications unread"
		}
		payload["unread"] = true
	case "read", "dismiss":
		if len(parts) != 2 {
			return nil, "Usage: /notifications " + parts[0] + " <id>"
		}
		payload["operation"] = strings.ToLower(parts[0])
		payload["id"] = parts[1]
	case "clear":
		if len(parts) != 1 {
			return nil, "Usage: /notifications clear"
		}
		payload["operation"] = "clear"
	case "action":
		if len(parts) < 2 || len(parts) > 3 {
			return nil, "Usage: /notifications action <id> [index]"
		}
		payload["operation"] = "action"
		payload["id"] = parts[1]
		if len(parts) == 3 {
			index, err := strconv.Atoi(parts[2])
			if err != nil || index < 0 {
				return nil, "Notification action index must be non-negative"
			}
			payload["index"] = index
		}
	case "severity", "category", "run", "agent", "route":
		if len(parts) != 2 {
			return nil, "Usage: /notifications " + parts[0] + " <value>"
		}
		payload[strings.ToLower(parts[0])] = parts[1]
	default:
		return nil, "Usage: /notifications [unread|read <id>|dismiss <id>|clear|severity <level>|category <name>]"
	}
	return payload, ""
}

func (m Model) workspaceSearchView() string {
	width := min(96, max(46, m.width-4))
	inner := width - 4
	title := lipgloss.NewStyle().Bold(true).Foreground(green).Width(inner).
		Align(lipgloss.Center).Render("Workspace search")
	query := render.Col(white).Render(truncate(m.searchQuery, max(1, inner-7)))
	header := render.Dim().Render("Find: ") + query
	if m.searchRoot != "" {
		header += "\n" + render.Dim().Render(truncate(m.searchRoot, inner))
	}

	visible := min(len(m.searchMatches), max(1, m.height-12))
	rows := make([]string, 0, max(1, visible))
	for _, match := range m.searchMatches[:visible] {
		location := fmt.Sprintf("%s:%d:%d", match.Path, match.Line, match.Column)
		text := strings.TrimSpace(match.Text)
		row := render.Col(lightBlue).Render(location)
		if text != "" {
			row += render.Dim().Render("  ") + render.Col(textColor).Render(text)
		}
		rows = append(rows, truncate(row, inner))
	}
	if len(rows) == 0 {
		rows = append(rows, render.Dim().Italic(true).Render("No matches"))
	}

	count := fmt.Sprintf("%d matching line(s)", m.searchMatchCount)
	if m.searchTruncated || visible < len(m.searchMatches) {
		count = fmt.Sprintf("showing %d of %d matching line(s)", visible, m.searchMatchCount)
	}
	footer := render.Dim().Render(count + " · any key closes")
	content := title + "\n\n" + header + "\n\n" + strings.Join(rows, "\n") + "\n\n" + footer
	return lipgloss.NewStyle().Width(width - 2).Border(lipgloss.RoundedBorder()).
		BorderForeground(dark).Background(black).Padding(1).Render(content)
}
