package sshutil

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mnofresno/mcp-ssh-secure/internal/audit"
	"github.com/mnofresno/mcp-ssh-secure/internal/config"
)

func TestBuildSSHCommandKeyMode(t *testing.T) {
	p := config.Profile{
		Host:            "example.com",
		Port:            2222,
		User:            "alice",
		KeyPath:         "/tmp/key",
		StrictHostKey:   true,
		ForceIPv4:       true,
		KnownHostsPath:  "/tmp/known_hosts",
		ConnectTimeoutS: 10,
		AuthMode:        "key",
	}
	cmd := buildSSHCommand(context.Background(), p, "uname -a", false, false)
	if filepath.Base(cmd.Path) != "ssh" {
		t.Fatalf("expected ssh binary, got %s", cmd.Path)
	}
	args := strings.Join(cmd.Args, " ")
	for _, want := range []string{"-p 2222", "-i /tmp/key", "alice@example.com", "StrictHostKeyChecking=yes", "BatchMode=yes", "NumberOfPasswordPrompts=0", "-4", "-n"} {
		if !strings.Contains(args, want) {
			t.Fatalf("missing arg %q in %s", want, args)
		}
	}
}

func TestBuildSSHCommandPasswordMode(t *testing.T) {
	p := config.Profile{Host: "h", Port: 22, User: "u", AuthMode: "password", PasswordFile: "/tmp/pw", ConnectTimeoutS: 5}
	cmd := buildSSHCommand(context.Background(), p, "id", false, false)
	if filepath.Base(cmd.Path) != "sshpass" {
		t.Fatalf("expected sshpass binary, got %s", cmd.Path)
	}
}

func TestKeyNeedsPassphraseFalseWithTempKey(t *testing.T) {
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen not found")
	}
	tmp := t.TempDir()
	key := filepath.Join(tmp, "id_rsa")
	cmd := exec.Command("ssh-keygen", "-q", "-t", "rsa", "-b", "2048", "-N", "", "-f", key)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("generate key: %v (%s)", err, string(out))
	}
	enc, err := keyNeedsPassphrase(key)
	if err != nil {
		t.Fatalf("key check error: %v", err)
	}
	if enc {
		t.Fatal("expected unencrypted key")
	}
}

func TestRunCmd(t *testing.T) {
	cmd := exec.Command("sh", "-c", "echo hi")
	out, err := runCmd(cmd, "")
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(out) != "hi" {
		t.Fatalf("unexpected output: %q", out)
	}
}

func TestRedact(t *testing.T) {
	in := "Password invalid token passphrase"
	out := redact(in)
	if strings.Contains(strings.ToLower(out), "password") {
		t.Fatal("password not redacted")
	}
}

func TestTimeoutContextBuild(t *testing.T) {
	p := config.Profile{Host: "h", Port: 22, User: "u", ConnectTimeoutS: 1, AuthMode: "agent"}
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	cmd := buildSSHCommand(ctx, p, "true", false, false)
	if cmd == nil {
		t.Fatal("nil cmd")
	}
}

func TestAddKeyToAgentNoAgent(t *testing.T) {
	if _, err := exec.LookPath("ssh-add"); err != nil {
		t.Skip("ssh-add not found")
	}
	old := os.Getenv("SSH_AUTH_SOCK")
	_ = os.Unsetenv("SSH_AUTH_SOCK")
	defer os.Setenv("SSH_AUTH_SOCK", old)
	err := addKeyToAgent(context.Background(), "/tmp/not-found", "")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestEnsureKeyReturnsEarlyWhenAlreadyLoadedInAgent(t *testing.T) {
	tmp := t.TempDir()
	binDir := filepath.Join(tmp, "bin")
	if err := os.Mkdir(binDir, 0o755); err != nil {
		t.Fatal(err)
	}

	pub := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBJgZ2aYy8z5L5YJtYl3N9J0W6w5R4eJ8hA4XrN2vQeQ test@example"
	keyPath := filepath.Join(tmp, "id_test")
	if err := os.WriteFile(keyPath, []byte("private"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath+".pub", []byte(pub+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	sshAddPath := filepath.Join(binDir, "ssh-add")
	sshAddScript := "#!/bin/sh\nif [ \"$1\" = \"-L\" ]; then\n  printf '%s\\n' '" + pub + "'\n  exit 0\nfi\necho unexpected ssh-add invocation >&2\nexit 1\n"
	if err := os.WriteFile(sshAddPath, []byte(sshAddScript), 0o755); err != nil {
		t.Fatal(err)
	}

	oldPath := os.Getenv("PATH")
	oldSock := os.Getenv("SSH_AUTH_SOCK")
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+oldPath)
	t.Setenv("SSH_AUTH_SOCK", filepath.Join(tmp, "agent.sock"))
	defer os.Setenv("PATH", oldPath)
	defer os.Setenv("SSH_AUTH_SOCK", oldSock)

	auditor, err := audit.New(filepath.Join(tmp, "audit.log"))
	if err != nil {
		t.Fatalf("audit logger: %v", err)
	}

	r := &Runner{
		cfg: &config.Config{
			Profiles: map[string]config.Profile{
				"p": {Host: "h", User: "u", Port: 22, ConnectTimeoutS: 1, KeyPath: keyPath, AuthMode: "agent"},
			},
		},
		auditor: auditor,
	}
	got, err := r.EnsureKey(context.Background(), "p", "")
	if err != nil {
		t.Fatalf("EnsureKey error: %v", err)
	}
	if got != "SSH key already loaded into ssh-agent" {
		t.Fatalf("unexpected message: %q", got)
	}
}
