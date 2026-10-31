package engine

import (
	"testing"

	"github.com/ryuma04/decoy/backend/internal/store"
)

func TestLLMActionSkipsOnlyNavigation(t *testing.T) {
	ev := store.StoredEvent{Type: "shell.command"}
	for raw, want := range map[string]bool{
		"cd /tmp": false, "ls -la": false, "pwd": false, "history": false, "exit": false,
		"history -c": true, "chattr +i /etc/passwd": true, "iptables -F": true, "nohup ./x &": true,
	} {
		got := llmAction(ev, map[string]any{"raw": raw}) != ""
		if got != want {
			t.Errorf("%q: sent to LLM = %v, want %v", raw, got, want)
		}
	}
}
