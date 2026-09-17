package app

import (
	"time"

	"github.com/charmbracelet/bubbles/textarea"
	"github.com/charmbracelet/bubbles/viewport"
)

// The Bubble Tea program remains a single root model, but mutable feature state
// is owned by the feature that renders and updates it. Embedding keeps the
// existing view helpers source-compatible while preventing the root from
// becoming the source of truth for every panel.
type setupFeature struct {
	input         textarea.Model
	setupLog      []string
	pendingPrompt string
}

type transcriptFeature struct {
	viewport        viewport.Model
	viewportContent string
	expandedEvents  map[string]bool
	blockCache      map[string]renderedBlock
	eventSpans      []eventSpan
	followOutput    bool
	selection       selectionState
	draftHistory    []string
	draftIndex      int
	pastedDraft     bool
}

type agentsFeature struct {
	collapsedAgents map[string]bool
	selectedAgent   int
	agentOffset     int
}

type findingsFeature struct {
	vulnViewport           viewport.Model
	selectedVuln           int
	vulnOffset             int
	reportFocus            string
	vulnerabilityCopied    bool
	vulnerabilityCopyError string
}

type workspaceFeature struct {
	dialog           workspaceDialog
	options          []string
	filtered         []string
	cursor           int
	modalChoice      int
	searchQuery      string
	searchRoot       string
	searchMatchCount int
	searchTruncated  bool
	searchMatches    []workspaceSearchMatch
}

type notificationFeature struct {
	toastQueue   []string
	seenMessages map[string]bool
	toast        string
	toastID      int
}

type protocolFeature struct {
	pendingDrafts        map[string]string
	outboundDrafts       map[string]string
	stateRevision        int
	collectionRevisions  map[string]int
	collectionAssemblies map[string]*collectionAssembly
	resyncRequested      map[string]bool
	resyncRequests       map[string]string
}

type recoveryFeature struct {
	errorText           string
	fatalError          error
	budgetPauseNotified bool
}

type presentationFeature struct {
	modal             modalMode
	focus             focusMode
	mcpOffset         int
	draggingScrollbar scrollbarTarget
	showSplash        bool
	splashStarted     time.Time
	splashFrame       int
	sweepFrame        int
}
