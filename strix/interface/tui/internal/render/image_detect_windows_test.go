//go:build windows

package render

import "testing"

func TestWindowsSkipsTerminalCapabilityQueries(t *testing.T) {
	if terminalCapabilityQueriesSupported() {
		t.Fatal("Windows terminals must not receive a DA1 query that cannot be drained")
	}
}
