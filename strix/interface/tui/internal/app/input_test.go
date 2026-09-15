package app

import (
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	"github.com/usestrix/strix/tui/internal/protocol"
)

type failingConn struct{}

func (*failingConn) Read([]byte) (int, error)  { return 0, io.EOF }
func (*failingConn) Write([]byte) (int, error) { return 0, errors.New("transport failed") }
func (*failingConn) Close() error              { return nil }

func inputModel(t *testing.T) Model {
	t.Helper()
	model := New(nil)
	model.showSplash = false
	model.ready = true
	model.width, model.height = 130, 40
	model.resizeViewport()
	return model
}

func TestInputGrowsWithContentUpToCap(t *testing.T) {
	model := inputModel(t)
	// The live composer opens at a single row, out of the trace's way.
	if got := model.input.Height(); got != 1 {
		t.Fatalf("empty composer height = %d, want 1", got)
	}
	model.input.SetValue(strings.Repeat("line\n", 4) + "line")
	model.resizeViewport()
	if got := model.input.Height(); got != 5 {
		t.Fatalf("5-line composer height = %d, want 5", got)
	}
	model.input.SetValue(strings.Repeat("line\n", 19) + "line")
	model.resizeViewport()
	if got := model.input.Height(); got != maxInputLines {
		t.Fatalf("20-line composer height = %d, want %d", got, maxInputLines)
	}
}

// The launch composer opens with room to breathe; the live one stays a single
// row until there is something to show, as it always has.
func TestComposerOpeningHeightPerMode(t *testing.T) {
	live := inputModel(t)
	if got := live.input.Height(); got != 1 {
		t.Fatalf("live composer opens at %d rows, want 1", got)
	}

	setup := inputModel(t)
	setup.snapshot.SetupMode = true
	setup.resizeViewport()
	if got := setup.input.Height(); got != minInputLines {
		t.Fatalf("launch composer opens at %d rows, want %d", got, minInputLines)
	}
}

// A prompt with no newline in it still has to grow the composer once it wraps.
func TestInputGrowsWithSoftWrappedLine(t *testing.T) {
	for _, setup := range []bool{false, true} {
		model := inputModel(t)
		model.snapshot.SetupMode = setup
		model.resizeViewport()
		floor, _ := model.composerBounds()
		if got := model.input.Height(); got != floor {
			t.Fatalf("setup=%v: empty composer height = %d, want floor %d", setup, got, floor)
		}
		width := model.input.Width()
		model.input.SetValue(strings.Repeat("x", width*5-1))
		model.resizeViewport()
		// Five rows of text; the textarea adds a trailing row when the last one
		// is full, so the cursor stays visible.
		if got := model.input.Height(); got < 5 || got > 6 {
			t.Fatalf("setup=%v: wrapped composer height = %d, want 5 or 6", setup, got)
		}
		model.input.SetValue(strings.Repeat("x", width*maxInputLines*2))
		model.resizeViewport()
		if got := model.input.Height(); got != maxInputLines {
			t.Fatalf("setup=%v: overlong composer height = %d, want %d", setup, got, maxInputLines)
		}
	}
}

func TestComposerMeasurementDoesNotResetLongInputScroll(t *testing.T) {
	input := newChatInput()
	input.Focus()
	input.SetWidth(30)
	input.SetHeight(3)
	value := strings.Join([]string{
		"first line is deliberately wide",
		"second line is deliberately wide",
		"third line is deliberately wide",
		"fourth line is deliberately wide",
		"last line remains visible at cursor",
	}, "\n")
	updated, _ := input.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(value), Paste: true})
	input = updated
	// Bubbles computes the scroll range from the rendered content. Render once,
	// then let a normal non-key event place the viewport at the cursor.
	_ = input.View()
	updated, _ = input.Update(struct{}{})
	input = updated
	before := ansi.Strip(input.View())
	if !strings.Contains(before, "last line") {
		t.Fatalf("test setup did not scroll to the cursor: %q", before)
	}

	_ = composerHeight(input)
	after := ansi.Strip(input.View())
	if after != before {
		t.Fatalf("measuring composer height moved its viewport:\n before %q\n  after %q", before, after)
	}
}

// The composer never takes more than a third of a short terminal.
func TestInputHeightCappedOnShortTerminal(t *testing.T) {
	model := inputModel(t)
	model.width, model.height = 130, 15
	model.input.SetValue(strings.Repeat("line\n", 10) + "line")
	model.resizeViewport()
	if got := model.input.Height(); got != 5 {
		t.Fatalf("composer height on a 15-row terminal = %d, want 5", got)
	}
}

// The rendered frame must be exactly the terminal size at every step of
// typing. A composer that renders one cell too wide gets re-wrapped into an
// extra row, which pushes the frame past the bottom of the terminal and makes
// the screen jump at wrap points.
func TestFrameFitsTerminalWhileTyping(t *testing.T) {
	sizes := [][2]int{{130, 40}, {100, 30}, {80, 24}}
	for _, setup := range []bool{false, true} {
		for _, size := range sizes {
			model := New(nil)
			model.showSplash, model.ready, model.focus = false, true, focusInput
			model.width, model.height = size[0], size[1]
			model.snapshot = protocol.Snapshot{SetupMode: setup, Model: "anthropic/claude-sonnet-4-5"}
			if !setup {
				model.snapshot.Agents = []protocol.Agent{{ID: "a1", Name: "recon", Status: "running"}}
			}
			model.resizeViewport()
			for i, r := range strings.Repeat("alpha bravo charlie delta echo foxtrot ", 6) {
				updated, _ := model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}})
				model = updated.(Model)
				rows := strings.Split(model.View(), "\n")
				if len(rows) != size[1] {
					t.Fatalf("setup=%v %v: after %d chars the frame is %d rows, want %d",
						setup, size, i+1, len(rows), size[1])
				}
				for row, line := range rows {
					if width := lipgloss.Width(line); width != size[0] {
						t.Fatalf("setup=%v %v: after %d chars row %d is %d cells, want %d",
							setup, size, i+1, row, width, size[0])
					}
				}
			}
		}
	}
}

// The launch column is anchored: growing the composer must not walk the
// wordmark and the prompt up the screen.
func TestLaunchColumnHoldsStillWhileComposerGrows(t *testing.T) {
	model := New(nil)
	model.showSplash, model.ready, model.focus = false, true, focusInput
	model.width, model.height = 130, 40
	model.snapshot = protocol.Snapshot{SetupMode: true}
	model.resizeViewport()
	composerRow := func() int {
		for row, line := range strings.Split(ansi.Strip(model.View()), "\n") {
			if strings.Contains(line, "╭") {
				return row
			}
		}
		return -1
	}
	want := composerRow()
	for i, r := range strings.Repeat("alpha bravo charlie delta echo ", 12) {
		updated, _ := model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}})
		model = updated.(Model)
		if got := composerRow(); got != want {
			t.Fatalf("after %d chars the composer moved to row %d, want %d (height %d)",
				i+1, got, want, model.input.Height())
		}
	}
	if model.input.Height() < 5 {
		t.Fatalf("composer only grew to %d rows; the test is not exercising growth", model.input.Height())
	}
}

func TestCtrlJInsertsNewline(t *testing.T) {
	model := inputModel(t)
	model.input.SetValue("hello")
	updated, _ := model.Update(tea.KeyMsg{Type: tea.KeyCtrlJ})
	model = updated.(Model)
	if got := model.input.Value(); got != "hello\n" {
		t.Fatalf("value after ctrl+j = %q, want %q", got, "hello\n")
	}
}

func TestTypedNewlinesBeyondVisibleHeightArePreserved(t *testing.T) {
	model := inputModel(t)
	model.input.SetValue("line 1")
	for i := 2; i <= 20; i++ {
		updated, _ := model.Update(tea.KeyMsg{Type: tea.KeyCtrlJ})
		model = updated.(Model)
		for _, r := range []rune("line " + string(rune('0'+i%10))) {
			updated, _ = model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}})
			model = updated.(Model)
		}
	}
	if got := strings.Count(model.input.Value(), "\n") + 1; got != 20 {
		t.Fatalf("composer preserved %d hard lines, want 20: %q", got, model.input.Value())
	}
	if got := model.input.Height(); got != maxInputLines {
		t.Fatalf("composer display height = %d, want cap %d", got, maxInputLines)
	}
}

func TestWindowsMultilinePasteNormalizesCRLFWithoutDroppingLines(t *testing.T) {
	model := inputModel(t)
	lines := make([]string, 20)
	for index := range lines {
		lines[index] = "line"
	}
	pasted := strings.Join(lines, "\r\n")
	updated, _ := model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(pasted), Paste: true})
	model = updated.(Model)

	want := strings.Join(lines, "\n")
	if got := model.input.Value(); got != want {
		t.Fatalf("pasted value changed:\n got %q\nwant %q", got, want)
	}
	if got := model.input.Height(); got != maxInputLines {
		t.Fatalf("pasted composer display height = %d, want cap %d", got, maxInputLines)
	}
}

func TestCtrlSSubmitsExactMultilineMessage(t *testing.T) {
	connection := &recordingConn{}
	model := inputModel(t)
	model.client = newClient(connection)
	model.snapshot.Agents = []protocol.Agent{{ID: "agent-1", Name: "Strix", Status: "running"}}
	want := "  first\nsecond \n"
	model.input.SetValue(want)
	updated, cmd := model.Update(tea.KeyMsg{Type: tea.KeyCtrlS})
	model = updated.(Model)
	if got := model.input.Value(); got != "" {
		t.Fatalf("composer not cleared after submit: %q", got)
	}
	if got := model.input.Height(); got != 1 {
		t.Fatalf("composer height after submit = %d, want 1", got)
	}
	envelope := commandFromCmd(t, cmd, connection)
	var payload struct {
		Message string `json:"message"`
	}
	if err := json.Unmarshal(envelope.Payload, &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Message != want {
		t.Fatalf("submitted message = %q, want exact value %q", payload.Message, want)
	}
}

func TestFailedSendRestoresExactDraft(t *testing.T) {
	model := inputModel(t)
	model.client = newClient(&failingConn{})
	model.snapshot.Agents = []protocol.Agent{{ID: "agent-1", Name: "Strix", Status: "running"}}
	want := "first\nsecond\nthird"
	model.input.SetValue(want)

	updated, cmd := model.Update(tea.KeyMsg{Type: tea.KeyCtrlS})
	model = updated.(Model)
	if cmd == nil {
		t.Fatal("submit returned no command")
	}
	sent, ok := cmd().(sentMsg)
	if !ok || sent.err == nil {
		t.Fatalf("send unexpectedly succeeded: %#v", sent)
	}
	updated, _ = model.Update(sent)
	model = updated.(Model)
	if got := model.input.Value(); got != want {
		t.Fatalf("restored draft = %q, want %q", got, want)
	}
}

func TestBackendRejectionRestoresExactDraft(t *testing.T) {
	connection := &recordingConn{}
	model := inputModel(t)
	model.client = newClient(connection)
	model.snapshot.Agents = []protocol.Agent{{ID: "agent-1", Name: "Strix", Status: "running"}}
	want := "first\nsecond\nthird"
	model.input.SetValue(want)

	updated, cmd := model.Update(tea.KeyMsg{Type: tea.KeyCtrlS})
	model = updated.(Model)
	sent, ok := cmd().(sentMsg)
	if !ok || sent.err != nil {
		t.Fatalf("send failed before backend response: %#v", sent)
	}
	updated, _ = model.Update(sent)
	model = updated.(Model)
	failed := protocol.CommandResult{
		OK:      false,
		Command: "agent.send_message",
		Error:   &protocol.CommandError{Code: "temporarily_unavailable", Message: "try again"},
	}
	model.handleEnvelope(protocol.Envelope{
		Version: protocol.Version, Type: "command_result", RequestID: sent.requestID, Payload: rawJSON(t, failed),
	})

	if got := model.input.Value(); got != want {
		t.Fatalf("restored draft = %q, want %q", got, want)
	}
	if model.errorText != "try again" {
		t.Fatalf("backend error = %q, want %q", model.errorText, "try again")
	}
}

func TestMalformedBackendResultRestoresDraftAndReleasesCommand(t *testing.T) {
	connection := &recordingConn{}
	model := inputModel(t)
	model.client = newClient(connection)
	model.snapshot.Agents = []protocol.Agent{{ID: "agent-1", Name: "Strix", Status: "running"}}
	want := "first\nsecond"
	model.input.SetValue(want)

	updated, cmd := model.Update(tea.KeyMsg{Type: tea.KeyCtrlS})
	model = updated.(Model)
	sent := cmd().(sentMsg)
	updated, _ = model.Update(sent)
	model = updated.(Model)
	model.handleEnvelope(protocol.Envelope{
		Version: protocol.Version, Type: "command_result", RequestID: sent.requestID, Payload: []byte("{"),
	})

	if model.input.Value() != want {
		t.Fatalf("malformed result lost draft: %q", model.input.Value())
	}
	if _, pending := model.client.ExpectedCommand(sent.requestID); pending {
		t.Fatal("malformed result left command permanently pending")
	}
}

func TestOversizedPromptIsKeptForEditing(t *testing.T) {
	model := inputModel(t)
	want := strings.Repeat("x", maxPromptBytes+1)
	model.input.SetValue(want)

	updated, cmd := model.Update(tea.KeyMsg{Type: tea.KeyCtrlS})
	model = updated.(Model)
	if cmd != nil {
		t.Fatal("oversized prompt was submitted")
	}
	if model.input.Value() != want {
		t.Fatal("oversized prompt was cleared")
	}
	if !strings.Contains(model.errorText, "256 KiB") {
		t.Fatalf("missing size error: %q", model.errorText)
	}
}

func TestDragSelectionInInputCopiesText(t *testing.T) {
	model := inputModel(t)
	copied := ""
	original := writeClipboard
	writeClipboard = func(text string) error {
		copied = text
		return nil
	}
	defer func() { writeClipboard = original }()

	model.input.SetValue("copy me please")
	model.resizeViewport()
	top := model.inputTop()

	updated, _ := model.updateMouse(tea.MouseMsg{
		X: 4, Y: top + 1, Button: tea.MouseButtonLeft, Action: tea.MouseActionPress,
	})
	model = updated.(Model)
	if !model.selection.dragging || model.selection.region != regionInput {
		t.Fatalf("press in the composer did not start an input selection: %+v", model.selection)
	}
	updated, _ = model.updateMouse(tea.MouseMsg{X: 10, Y: top + 1, Action: tea.MouseActionMotion})
	model = updated.(Model)
	updated, cmd := model.updateMouse(tea.MouseMsg{Action: tea.MouseActionRelease})
	model = updated.(Model)
	if cmd == nil {
		t.Fatal("input selection release produced no copy command")
	}
	if msg, ok := cmd().(selectionCopiedMsg); !ok || msg.err != nil {
		t.Fatalf("unexpected copy result: %#v", cmd())
	}
	if copied != "copy me" {
		t.Fatalf("copied %q, want %q", copied, "copy me")
	}
}

func TestEnterNeverSendsUnbracketedPaste(t *testing.T) {
	connection := &recordingConn{}
	model := inputModel(t)
	model.client = newClient(connection)
	model.snapshot.SetupMode = true
	for _, line := range []string{"/target https://example.invalid", "Unicode café 日本語", "  indented"} {
		updated, _ := model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(line)})
		model = updated.(Model)
		updated, _ = model.Update(tea.KeyMsg{Type: tea.KeyEnter})
		model = updated.(Model)
	}
	if connection.Len() != 0 || !strings.Contains(model.input.Value(), "\nUnicode café 日本語\n") {
		t.Fatalf("unbracketed paste submitted or changed: %q", model.input.Value())
	}
}
