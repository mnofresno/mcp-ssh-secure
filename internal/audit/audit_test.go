package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNewWriteAndTailRedactsSecrets(t *testing.T) {
	tmp := t.TempDir()
	logPath := filepath.Join(tmp, "state", "audit.log")

	logger, err := New(logPath)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	info, err := os.Stat(logPath)
	if err != nil {
		t.Fatalf("stat log file: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("unexpected permissions: %o", info.Mode().Perm())
	}

	logger.Write(Event{Action: "run_sudo", Status: "error", Detail: "Password invalid for token abc"})
	if err := os.WriteFile(logPath, []byte("{\"detail\":\"manual password leak\"}\n"), 0o600); err != nil {
		t.Fatalf("seed manual line: %v", err)
	}
	logger.Write(Event{Action: "run_ssh", Status: "ok", Detail: "Passphrase requested"})

	out, err := logger.Tail(10)
	if err != nil {
		t.Fatalf("Tail() error = %v", err)
	}
	lower := strings.ToLower(out)
	for _, secret := range []string{"password", "passphrase", "token"} {
		if strings.Contains(lower, secret) {
			t.Fatalf("tail leaked %q: %s", secret, out)
		}
	}
	if !strings.Contains(out, "[redacted]") {
		t.Fatalf("tail did not redact content: %s", out)
	}
}

func TestTailWithMinimumLines(t *testing.T) {
	tmp := t.TempDir()
	logPath := filepath.Join(tmp, "audit.log")

	logger, err := New(logPath)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	logger.Write(Event{Action: "a", Status: "ok", Detail: "first"})
	logger.Write(Event{Action: "b", Status: "ok", Detail: "second"})

	out, err := logger.Tail(0)
	if err != nil {
		t.Fatalf("Tail() error = %v", err)
	}
	if strings.Contains(out, "first") {
		t.Fatalf("expected only the latest line, got %s", out)
	}
	if !strings.Contains(out, "second") {
		t.Fatalf("missing latest line: %s", out)
	}
}
