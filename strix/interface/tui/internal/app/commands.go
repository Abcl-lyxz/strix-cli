package app

import (
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

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
	{"connect", "", "connect a provider and discover models"},
	{"models", "", "choose a model connection"},
	{"routing", "", "advanced route priorities and request limits"},
	{"mcp", "", "configure MCP connections for the next scan"},
	{"notify-settings", "", "set notification severity and alert preferences"},
	{"settings", "", "edit all settings in forms"},
	{"attach", "[path]", "attach a local file or folder"},
	{"sessions", "", "browse and resume local runs"},
	{"retry", "", "retry the interrupted turn using saved results"},
	{"new", "", "start a new session"},
	{"editor", "", "compose in your external editor"},

	{"help", "", "show every command and shortcut"},
	{"config", "[clear]", "show configuration or clear model credentials"},
	{"model", "<provider/model>", "set the model route"},
	{"apikey", "[key|clear]", "open secure input, save, or remove the API key"},
	{"baseurl", "<url|clear>", "set a custom OpenAI-compatible API URL"},
	{"routes", "[select <name>]", "list model routes or select one to edit"},
	{"notifications", "[unread|read <id>|dismiss <id>|clear]", "open the notification inbox"},
	{"storage", "", "show exact run and global storage paths"},
	{"reasoning", "<level>", "none|minimal|low|medium|high|xhigh|max"},
	{"target", "<url|repo|path>", "add a scan target"},
	{"untarget", "<target|all>", "remove one or all targets"},
	{"targets", "", "show queued targets"},
	{"find", "<text>", "search local workspace without an AI turn"},
	{"instruction", "<text|clear>", "set the scan instruction"},
	{"mode", "<quick|standard|deep>", "set scan depth"},
	{"budget", "<usd|off>", "set or remove the cost limit"},
	{"turns", "<n>", "set maximum turns per agent"},
	{"agents", "[n]", "set the setup limit or focus live agents"},
	{"scope", "<auto|diff|full>", "set repository scope"},
	{"diff-base", "<ref|clear>", "set the base ref for diff scope"},
	{"streaming", "<on|off>", "toggle streamed model responses"},
	{"cache", "<on|off>", "toggle model prompt caching"},
	{"timeout", "<seconds>", "set the model request timeout"},
	{"toolcalls", "<n>", "set maximum tool calls per turn"},
	{"images", "<n>", "set images retained in agent context"},
	{"start", "", "launch with the current setup"},
	{"status", "", "show model and run status"},
	{"viewer", "", "open the live report viewer"},
	{"agent", "<id|name>", "select a live agent"},
	{"findings", "", "focus the findings panel"},
	{"trace", "", "focus the agent trace"},
	{"follow", "<on|off>", "toggle automatic trace scrolling"},
	{"stop", "", "stop the selected agent"},
	{"clear", "", "clear local notices"},
	{"quit", "", "quit Strix"},
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

// inputView masks credentials while retaining the real value only in the
// textarea model until submission. No snapshot or command result contains it.
func (m Model) inputView() string {
	value := m.input.Value()
	lower := strings.ToLower(value)
	const prefix = "/apikey "
	if !strings.HasPrefix(lower, prefix) || len(value) <= len(prefix) {
		return m.input.View()
	}
	masked := m.input
	masked.SetValue(value[:len(prefix)] + strings.Repeat("•", utf8.RuneCountInString(value[len(prefix):])))
	masked.CursorEnd()
	return masked.View()
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

func (m Model) submitSlashCommand(value string) (tea.Model, tea.Cmd, bool) { //nolint:gocyclo
	name, argument, known := slashParts(value)
	if !known {
		return m, nil, false
	}

	if strings.TrimSpace(argument) == "" {
		switch name {
		case "connect", "models", "model":
			cmd := m.openWorkspace("providers", "Providers", "providers.list")
			return m, cmd, true
		case "routing":
			cmd := m.openWorkspace("routing", "Advanced routing", "providers.list")
			return m, cmd, true
		case "config", "settings", "reasoning", "streaming", "timeout", "cache", "toolcalls", "images":
			cmd := m.openWorkspace("settings", "Settings", "settings.list")
			return m, cmd, true
		case "baseurl":
			m.openForm("Provider endpoint", "config.update", map[string]any{}, inputField("api_base", "Base URL", "text", m.snapshot.APIBase))
			return m, nil, true
		case "retry":
			return m, send(m.client, "scan.retry", map[string]any{}), true
		case "sessions":
			cmd := m.openWorkspace("sessions", "Local sessions", "sessions.list")
			return m, cmd, true
		case "notifications":
			cmd := m.openWorkspace("notifications", "Notifications", "notifications.manage")
			return m, cmd, true
		case "new":
			return m, send(m.client, "scan.new", map[string]any{}), true
		case "editor":
			return m, m.externalEditor(), true
		case "mcp":
			m.openForm("MCP connection · next scan", "mcp.update", map[string]any{}, inputField("name", "Name", "text", ""), inputField("transport", "Transport: http or stdio", "text", "http"), inputField("url", "HTTP endpoint", "text", ""), inputField("command", "Executable (stdio)", "text", ""), inputField("args", "Arguments (JSON array)", "text", "[]"), inputField("token", "Bearer token (optional)", "secret", ""), inputField("persist", "Save as default: true or false", "boolean", false))
			return m, nil, true
		case "notify-settings":
			m.openForm("Notification preferences", "notifications.preferences", map[string]any{}, inputField("category", "Category: runtime, security, model, scan, storage", "text", "runtime"), inputField("minimum_severity", "Minimum: info, warning, error, critical", "text", "warning"), inputField("immediate", "Show alerts: true or false", "boolean", true))
			return m, nil, true
		case "attach":
			m.openForm("Attach a file or folder", "attachments.add", map[string]any{}, inputField("path", "Local path", "text", ""), inputField("role", "Role: context or target", "text", "context"))
			return m, nil, true
		case "target":
			m.openForm("Add a target", "setup.add_target", map[string]any{}, inputField("target", "URL, repository, or local path", "text", ""))
			return m, nil, true
		case "mode", "budget", "turns", "agents", "scope", "diff-base":
			field := map[string]string{"mode": "scan_mode", "budget": "max_budget_usd", "turns": "max_turns", "agents": "max_agents", "scope": "scope_mode", "diff-base": "diff_base"}[name]
			kind := "text"
			if name == "budget" || name == "turns" || name == "agents" {
				kind = "number"
			}
			m.openForm("Scan "+name, "setup.configure", map[string]any{}, inputField(field, name, kind, ""))
			return m, nil, true
		}
	}
	if name == "attach" {
		return m, send(m.client, "attachments.add", map[string]any{"path": argument, "role": "context"}), true
	}
	switch name {
	case "_partial":
		m.input.SetValue("/" + argument)
		m.input.CursorEnd()
		return m, m.slashError("Incomplete command; press Tab to complete it"), true
	case "help":
		m.openModal(modalHelp)
		return m, nil, true
	case "config":
		if strings.EqualFold(argument, "clear") {
			if cmd := m.requireSetup(name); cmd != nil {
				return m, cmd, true
			}
			return m, send(m.client, "config.update", map[string]any{"model": nil, "api_key": nil, "api_base": nil}), true
		}
		if argument != "" {
			return m, m.slashError("Usage: /config [clear]"), true
		}
		m.openModal(modalConfig)
		return m, nil, true
	case "model", "apikey", "baseurl", "reasoning", "streaming", "cache", "timeout", "toolcalls", "images":
		return m.submitConfigCommand(name, argument)
	case "routes":
		parts := strings.Fields(argument)
		if len(parts) == 0 {
			return m, send(m.client, "routes.manage", map[string]any{"operation": "list"}), true
		}
		if len(parts) == 2 && strings.EqualFold(parts[0], "select") {
			return m, send(m.client, "routes.manage", map[string]any{"operation": "select", "name": parts[1]}), true
		}
		return m, m.slashError("Usage: /routes [select <name>]"), true
	case "notifications":
		payload, err := notificationCommandPayload(argument)
		if err != "" {
			return m, m.slashError(err), true
		}
		return m, send(m.client, "notifications.manage", payload), true
	case "storage":
		if strings.TrimSpace(argument) != "" {
			return m, m.slashError("Usage: /storage"), true
		}
		return m, send(m.client, "storage.show", map[string]any{}), true
	case "target":
		if cmd := m.requireSetup(name); cmd != nil {
			return m, cmd, true
		}
		argument, cmd, ok := requiredArgument(&m, name, argument, "<url|repo|path>")
		if !ok {
			return m, cmd, true
		}
		return m, send(m.client, "setup.add_target", map[string]any{"target": argument}), true
	case "untarget":
		if cmd := m.requireSetup(name); cmd != nil {
			return m, cmd, true
		}
		argument, cmd, ok := requiredArgument(&m, name, argument, "<target|all>")
		if !ok {
			return m, cmd, true
		}
		if strings.EqualFold(argument, "all") {
			return m, send(m.client, "setup.clear_targets", map[string]any{}), true
		}
		return m, send(m.client, "setup.remove_target", map[string]any{"target": argument}), true
	case "targets":
		if len(m.snapshot.Targets) == 0 {
			return m, m.slashInfo("No targets queued; a prompt can use the current directory"), true
		}
		return m, m.slashInfo(fmt.Sprintf("%d target(s): %s", m.snapshot.TargetCount, strings.Join(m.snapshot.Targets, ", "))), true
	case "find":
		argument, cmd, ok := requiredArgument(&m, name, argument, "<text>")
		if !ok {
			return m, cmd, true
		}
		return m, send(m.client, "workspace.find", map[string]any{"query": argument}), true
	case "instruction":
		if cmd := m.requireSetup(name); cmd != nil {
			return m, cmd, true
		}
		if strings.EqualFold(argument, "clear") {
			argument = ""
		} else if argument == "" {
			return m, m.slashError("Usage: /instruction <text|clear>"), true
		}
		return m, send(m.client, "setup.set_instruction", map[string]any{"instruction": argument}), true
	case "mode", "budget", "turns", "scope", "diff-base":
		if cmd := m.requireSetup(name); cmd != nil {
			return m, cmd, true
		}
		return m.submitSetupCommand(name, argument)
	case "agents":
		if m.snapshot.SetupMode {
			if argument == "" {
				return m, m.slashInfo(fmt.Sprintf("Maximum active agents: %d", m.snapshot.MaxAgents)), true
			}
			return m.submitSetupCommand(name, argument)
		}
		m.focus = focusAgents
		m.input.Blur()
		return m, nil, true
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
		key := "missing"
		if m.snapshot.APIKeyConfigured {
			key = "configured"
		}
		return m, m.slashInfo(fmt.Sprintf("%s · model %s · API key %s · %d agent(s)", m.snapshot.ScanState, emptyAs(m.snapshot.Model, "not set"), key, len(m.snapshot.Agents))), true
	case "viewer":
		return m, send(m.client, "viewer.open", map[string]any{}), true
	case "agent":
		if m.snapshot.SetupMode {
			return m, m.slashError("/agent is available during a scan"), true
		}
		argument, cmd, ok := requiredArgument(&m, name, argument, "<id|name>")
		if !ok {
			return m, cmd, true
		}
		needle := strings.ToLower(argument)
		for index, agent := range m.snapshot.Agents {
			if strings.EqualFold(agent.ID, argument) || strings.EqualFold(agent.Name, argument) || strings.Contains(strings.ToLower(agent.Name), needle) {
				m.selectedAgent = index
				m.focus = focusAgents
				m.ensureAgentVisible()
				m.refreshViewport()
				return m, nil, true
			}
		}
		return m, m.slashError("No matching agent: " + argument), true
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
	case "follow":
		enabled, ok := parseToggle(argument)
		if !ok {
			return m, m.slashError("Usage: /follow <on|off>"), true
		}
		m.followOutput = enabled
		if enabled {
			m.viewport.GotoBottom()
		}
		return m, m.slashInfo("Trace follow " + map[bool]string{true: "enabled", false: "disabled"}[enabled]), true
	case "stop":
		if m.snapshot.SetupMode || !m.selectedAgentCanStop() {
			return m, m.slashError("No stoppable agent is selected"), true
		}
		m.modalChoice = 1
		m.openModal(modalStop)
		return m, nil, true
	case "clear":
		m.setupLog = nil
		m.errorText = ""
		m.toast = ""
		m.resizeViewport()
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
	return m, nil, false
}

func (m Model) submitConfigCommand(name, argument string) (tea.Model, tea.Cmd, bool) {
	payload := map[string]any{}
	switch name {
	case "model":
		value, _, ok := requiredArgument(&m, name, argument, "<provider/model>")
		if !ok {
			m.openModal(modalConfig)
			return m, nil, true
		}
		payload["model"] = value
	case "apikey":
		if strings.TrimSpace(argument) == "" {
			m.openModal(modalAPIKey)
			return m, nil, true
		}
		value, cmd, ok := requiredArgument(&m, name, argument, "<key|clear>")
		if !ok {
			return m, cmd, true
		}
		if strings.EqualFold(value, "clear") {
			payload["api_key"] = nil
		} else {
			payload["api_key"] = value
		}
	case "baseurl":
		value, cmd, ok := requiredArgument(&m, name, argument, "<url|clear>")
		if !ok {
			return m, cmd, true
		}
		if strings.EqualFold(value, "clear") {
			payload["api_base"] = nil
		} else {
			payload["api_base"] = value
		}
	case "reasoning":
		value, cmd, ok := requiredArgument(&m, name, argument, "<level>")
		if !ok {
			return m, cmd, true
		}
		payload["reasoning_effort"] = strings.ToLower(value)
	case "streaming", "cache":
		enabled, ok := parseToggle(argument)
		if !ok {
			return m, m.slashError("Usage: /" + name + " <on|off>"), true
		}
		field := map[string]string{"streaming": "streaming_enabled", "cache": "prompt_cache"}[name]
		payload[field] = enabled
	case "timeout", "toolcalls", "images":
		value, err := strconv.Atoi(strings.TrimSpace(argument))
		if err != nil || value < 0 || (name == "timeout" && value == 0) {
			return m, m.slashError("Usage: /" + name + " <non-negative integer>"), true
		}
		field := map[string]string{"timeout": "llm_timeout", "toolcalls": "max_tool_calls_per_turn", "images": "max_context_images"}[name]
		payload[field] = value
	}
	return m, send(m.client, "config.update", payload), true
}

func (m Model) submitSetupCommand(name, argument string) (tea.Model, tea.Cmd, bool) {
	payload := map[string]any{}
	switch name {
	case "mode":
		payload["scan_mode"] = strings.ToLower(strings.TrimSpace(argument))
	case "budget":
		if strings.EqualFold(strings.TrimSpace(argument), "off") {
			payload["max_budget_usd"] = nil
		} else {
			value, err := strconv.ParseFloat(strings.TrimSpace(argument), 64)
			if err != nil || value <= 0 {
				return m, m.slashError("Usage: /budget <positive-usd|off>"), true
			}
			payload["max_budget_usd"] = value
		}
	case "turns", "agents":
		value, err := strconv.Atoi(strings.TrimSpace(argument))
		if err != nil || value <= 0 || (name == "agents" && value < 2) {
			return m, m.slashError("Usage: /" + name + " <positive integer>"), true
		}
		field := map[string]string{"turns": "max_turns", "agents": "max_agents"}[name]
		payload[field] = value
	case "scope":
		payload["scope_mode"] = strings.ToLower(strings.TrimSpace(argument))
	case "diff-base":
		if strings.EqualFold(strings.TrimSpace(argument), "clear") {
			payload["diff_base"] = nil
		} else if strings.TrimSpace(argument) == "" {
			return m, m.slashError("Usage: /diff-base <ref|clear>"), true
		} else {
			payload["diff_base"] = strings.TrimSpace(argument)
		}
	}
	return m, send(m.client, "setup.configure", payload), true
}

func emptyAs(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func (m Model) commandHelpView() string {
	width := min(76, max(44, m.width-4))
	inner := width - 4
	title := lipgloss.NewStyle().Bold(true).Foreground(green).Width(inner).Align(lipgloss.Center).Render("Strix Help · command palette")
	section := func(label, commands string) string {
		return render.Bold(green).Render(label) + "\n" + render.Col(textColor).Render(commands)
	}
	body := strings.Join([]string{
		section("Configure", "/config  /model  /apikey  /baseurl  /routes  /reasoning\n/streaming  /cache  /timeout  /toolcalls  /images"),
		section("Prepare", "/target  /untarget  /targets  /find  /instruction  /mode\n/budget  /turns  /agents  /scope  /diff-base  /start"),
		section("Control", "/status  /viewer  /notifications  /storage  /agent  /agents\n/findings  /trace  /follow  /stop  /clear  /quit"),
		section("Keys", "F1 help · Tab complete/switch · Ctrl+J newline · Ctrl+O viewer\nEsc stop agent · Ctrl+Q quit · arrows navigate"),
	}, "\n\n")
	footer := render.Dim().Render("Type / to search commands · press any key to close")
	content := title + "\n\n" + lipgloss.NewStyle().Width(inner).Render(body) + "\n\n" + footer
	return lipgloss.NewStyle().Width(width - 2).Border(lipgloss.RoundedBorder()).
		BorderForeground(green).Background(black).Padding(1).Render(content)
}

func (m Model) configurationView() string {
	width := min(72, max(46, m.width-4))
	inner := width - 4
	keyState := render.Col(amber).Render("not set")
	if m.snapshot.APIKeyConfigured {
		keyState = render.Col(green).Render("configured (hidden)")
	}
	baseURL := emptyAs(m.snapshot.APIBase, "provider default")
	status := []string{
		fmt.Sprintf("%-13s %s", "Model", emptyAs(m.snapshot.Model, "not set")),
		fmt.Sprintf("%-13s %s", "API key", keyState),
		fmt.Sprintf("%-13s %s", "Base URL", baseURL),
		fmt.Sprintf("%-13s %s", "Reasoning", m.snapshot.ReasoningEffort),
		fmt.Sprintf("%-13s %s", "Streaming", onOff(m.snapshot.StreamingEnabled)),
		fmt.Sprintf("%-13s %s", "Prompt cache", onOff(m.snapshot.PromptCache)),
		fmt.Sprintf("%-13s %ds · %d tool calls · %d images", "Limits", m.snapshot.LLMTimeout, m.snapshot.MaxToolCallsPerTurn, m.snapshot.MaxContextImages),
	}
	for index, line := range status {
		status[index] = truncate(line, inner)
	}
	commands := render.Bold(green).Render("Change from the composer") + "\n" +
		render.Col(textColor).Render("/model openrouter/openai/gpt-5.4\n/apikey  (opens secure input)\n/baseurl http://localhost:11434/v1\n/reasoning high\n/streaming on · /cache on\n/timeout 300 · /toolcalls 32 · /images 3")
	warning := ""
	if m.snapshot.ConfigEnvOverride {
		warning = "\n\n" + render.Col(amber).Render("Environment variables currently override one or more saved LLM values.")
	}
	title := lipgloss.NewStyle().Bold(true).Foreground(green).Width(inner).Align(lipgloss.Center).Render("Model & runtime configuration")
	footer := render.Dim().Render("Saved privately in ~/.strix/cli-config.json · any key closes")
	content := title + "\n\n" + strings.Join(status, "\n") + "\n\n" + commands + warning + "\n\n" + footer
	return lipgloss.NewStyle().Width(width - 2).Border(lipgloss.RoundedBorder()).
		BorderForeground(green).Background(black).Padding(1).Render(content)
}

func onOff(value bool) string {
	if value {
		return "on"
	}
	return "off"
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

func (m Model) apiKeyCredentialView() string {
	width := min(58, max(30, m.width-4))
	inner := width - 4
	title := lipgloss.NewStyle().Bold(true).Foreground(green).Width(inner).
		Align(lipgloss.Center).Render("Model API key")
	secret := m.apiKeyInput
	secret.Width = max(10, inner-2)
	body := render.Dim().Render("The key is masked and never returned to the UI.") +
		"\n\n" + secret.View()
	if m.apiKeyError != "" {
		body += "\n\n" + render.Col(red).Render(truncate(m.apiKeyError, inner))
	}
	footer := render.Dim().Render("enter save · esc cancel · /apikey clear removes it")
	content := title + "\n\n" + lipgloss.NewStyle().Width(inner).Render(body) +
		"\n\n" + truncate(footer, inner)
	return lipgloss.NewStyle().Width(width - 2).Border(lipgloss.RoundedBorder()).
		BorderForeground(dark).Background(black).Padding(1).Render(content)
}
