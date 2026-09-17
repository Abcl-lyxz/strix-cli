package protocol

import (
	"reflect"
	"testing"
)

func TestProtocolVersionAndCapabilities(t *testing.T) {
	if Version != 8 {
		t.Fatalf("protocol version = %d, want 8", Version)
	}
	wantCapabilities := []string{
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
		"provider-adapters-v2",
		"automatic-task-router",
		"read-only-viewer",
		"typed-command-results",
	}
	if !reflect.DeepEqual(Capabilities, wantCapabilities) {
		t.Fatalf("capabilities = %#v, want %#v", Capabilities, wantCapabilities)
	}

}
