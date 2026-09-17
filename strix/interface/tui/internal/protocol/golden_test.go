package protocol

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

type goldenContract struct {
	Version   int        `json:"version"`
	Envelopes []Envelope `json:"envelopes"`
}

func TestProtocolV8SharedGoldenFixture(t *testing.T) {
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate golden test source")
	}
	fixture := filepath.Join(filepath.Dir(source), "..", "..", "..", "..", "..", "tests", "fixtures", "protocol_v8_contract.json")
	raw, err := os.ReadFile(fixture)
	if err != nil {
		t.Fatal(err)
	}
	var contract goldenContract
	if err := json.Unmarshal(raw, &contract); err != nil {
		t.Fatal(err)
	}
	if contract.Version != Version {
		t.Fatalf("fixture version = %d, protocol version = %d", contract.Version, Version)
	}
	if len(contract.Envelopes) != 6 {
		t.Fatalf("fixture envelopes = %d, want 6", len(contract.Envelopes))
	}
	for _, envelope := range contract.Envelopes {
		if envelope.Version != Version || envelope.Type == "" || len(envelope.Payload) == 0 {
			t.Fatalf("invalid envelope: %#v", envelope)
		}
	}
}
