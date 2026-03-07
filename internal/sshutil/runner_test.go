package sshutil

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mnofresno/mcp-ssh-secure/internal/config"
)

func TestBuildSSHCommandKeyMode(t *testing.T) {
	p := config.Profile{
		Host:            "example.com",
		Port:            2222,
		User:            "alice",
		KeyPath:         "/tmp/key",
		StrictHostKey:   true,
		KnownHostsPath:  "/tmp/known_hosts",
		ConnectTimeoutS: 10,
		AuthMode:        "key",
	}
	cmd := buildSSHCommand(context.Background(), p, "uname -a", false)
	if filepath.Base(cmd.Path) != "ssh" {
		t.Fatalf("expected ssh binary, got %s", cmd.Path)
	}
	args := strings.Join(cmd.Args, " ")
	for _, want := range []string{"-p 2222", "-i /tmp/key", "alice@example.com", "StrictHostKeyChecking=yes"} {
		if !strings.Contains(args, want) {
			t.Fatalf("missing arg %q in %s", want, args)
		}
	}
}

func TestBuildSSHCommandPasswordMode(t *testing.T) {
	p := config.Profile{Host: "h", Port: 22, User: "u", AuthMode: "password", PasswordFile: "/tmp/pw", ConnectTimeoutS: 5}
	cmd := buildSSHCommand(context.Background(), p, "id", false)
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
	cmd := buildSSHCommand(ctx, p, "true", false)
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
