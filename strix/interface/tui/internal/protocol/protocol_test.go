package protocol

import (
	"reflect"
	"testing"
)

func TestProtocolVersionAndCapabilities(t *testing.T) {
	if Version != 7 {
		t.Fatalf("protocol version = %d, want 7", Version)
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
	}
	if !reflect.DeepEqual(Capabilities, wantCapabilities) {
		t.Fatalf("capabilities = %#v, want %#v", Capabilities, wantCapabilities)
	}

}
