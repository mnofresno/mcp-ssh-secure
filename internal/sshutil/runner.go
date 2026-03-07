package sshutil

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/mnofresno/mcp-ssh-secure/internal/audit"
	"github.com/mnofresno/mcp-ssh-secure/internal/config"
)

type Runner struct {
	cfg     *config.Config
	auditor *audit.Logger
}

func NewRunner(cfg *config.Config, auditor *audit.Logger) *Runner {
	return &Runner{cfg: cfg, auditor: auditor}
}

func (r *Runner) EnsureKey(ctx context.Context, profileName, passphrase string) (string, error) {
	p, ok := r.cfg.Profile(profileName)
	if !ok {
		return "", fmt.Errorf("unknown profile: %s", profileName)
	}
	if p.KeyPath == "" {
		return "", fmt.Errorf("profile %s has no key_path", profileName)
	}

	encrypted, err := keyNeedsPassphrase(p.KeyPath)
	if err != nil {
		r.audit("ensure_key", profileName, "error", err.Error())
		return "", err
	}
	if encrypted && passphrase == "" {
		r.audit("ensure_key", profileName, "blocked", "passphrase required")
		return "", errors.New("SSH key has passphrase. Ask user for passphrase and call ensure_ssh_agent_key again with passphrase")
	}

	if err := addKeyToAgent(ctx, p.KeyPath, passphrase); err != nil {
		r.audit("ensure_key", profileName, "error", err.Error())
		return "", err
	}
	r.audit("ensure_key", profileName, "ok", "key loaded in ssh-agent")
	if encrypted {
		return "SSH key with passphrase loaded into ssh-agent for this OS session", nil
	}
	return "SSH key loaded into ssh-agent", nil
}

func (r *Runner) RunSSH(profileName, command string, timeout time.Duration, allocateTTY bool) (string, error) {
	p, ok := r.cfg.Profile(profileName)
	if !ok {
		return "", fmt.Errorf("unknown profile: %s", profileName)
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := buildSSHCommand(ctx, p, command, allocateTTY)
	out, err := runCmd(cmd, "")
	if err != nil {
		r.audit("run_ssh", profileName, "error", err.Error())
		return out, err
	}
	r.audit("run_ssh", profileName, "ok", "command executed")
	return out, nil
}

func (r *Runner) RunSudoSSH(profileName, command string, timeout time.Duration, overridePassword string) (string, error) {
	p, ok := r.cfg.Profile(profileName)
	if !ok {
		return "", fmt.Errorf("unknown profile: %s", profileName)
	}

	password := overridePassword
	if password == "" {
		if p.SudoPasswordFile == "" {
			return "", fmt.Errorf("profile %s has no sudo_password_file and no override provided", profileName)
		}
		b, err := os.ReadFile(p.SudoPasswordFile)
		if err != nil {
			return "", fmt.Errorf("read sudo password file: %w", err)
		}
		password = strings.TrimSpace(string(b))
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	wrapped := fmt.Sprintf("sudo -S -p '' bash -lc %q", command)
	cmd := buildSSHCommand(ctx, p, wrapped, true)
	out, err := runCmd(cmd, password+"\n")
	if err != nil {
		r.audit("run_sudo", profileName, "error", err.Error())
		return out, err
	}
	r.audit("run_sudo", profileName, "ok", "sudo command executed")
	return out, nil
}

func (r *Runner) ReadAuditTail(lines int) (string, error) {
	return r.auditor.Tail(lines)
}

func (r *Runner) audit(action, profile, status, detail string) {
	r.auditor.Write(audit.Event{Action: action, Profile: profile, Status: status, Detail: redact(detail)})
}

func runCmd(cmd *exec.Cmd, stdin string) (string, error) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}

	err := cmd.Run()
	combined := strings.TrimSpace(stdout.String())
	if serr := strings.TrimSpace(stderr.String()); serr != "" {
		if combined != "" {
			combined += "\n"
		}
		combined += serr
	}
	if err != nil {
		return combined, fmt.Errorf("command failed: %w", err)
	}
	return combined, nil
}

func buildSSHCommand(ctx context.Context, p config.Profile, remoteCommand string, tty bool) *exec.Cmd {
	args := []string{"-o", fmt.Sprintf("ConnectTimeout=%d", p.ConnectTimeoutS), "-o", "BatchMode=no", "-p", fmt.Sprintf("%d", p.Port)}
	if p.StrictHostKey {
		args = append(args, "-o", "StrictHostKeyChecking=yes")
	} else {
		args = append(args, "-o", "StrictHostKeyChecking=accept-new")
	}
	if p.KnownHostsPath != "" {
		args = append(args, "-o", fmt.Sprintf("UserKnownHostsFile=%s", p.KnownHostsPath))
	}
	if p.KeyPath != "" && (p.AuthMode == "key" || p.AuthMode == "agent") {
		args = append(args, "-i", p.KeyPath)
	}
	if tty {
		args = append(args, "-tt")
	}

	target := fmt.Sprintf("%s@%s", p.User, p.Host)

	if p.AuthMode == "password" {
		pwFile := p.PasswordFile
		sshArgs := append(args, target, remoteCommand)
		args = []string{"-f", pwFile, "ssh"}
		args = append(args, sshArgs...)
		return exec.CommandContext(ctx, "sshpass", args...)
	}

	args = append(args, target, remoteCommand)
	return exec.CommandContext(ctx, "ssh", args...)
}

func keyNeedsPassphrase(keyPath string) (bool, error) {
	cmd := exec.Command("ssh-keygen", "-y", "-P", "", "-f", keyPath)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	cmd.Stdout = ioDiscard{}
	err := cmd.Run()
	if err == nil {
		return false, nil
	}
	e := strings.ToLower(stderr.String())
	if strings.Contains(e, "incorrect passphrase") || strings.Contains(e, "load failed") || strings.Contains(e, "error in libcrypto") {
		return true, nil
	}
	return false, fmt.Errorf("cannot inspect key passphrase status: %w (%s)", err, strings.TrimSpace(stderr.String()))
}

func addKeyToAgent(ctx context.Context, keyPath, passphrase string) error {
	cmd := exec.CommandContext(ctx, "ssh-add", keyPath)
	var stderr bytes.Buffer
	cmd.Stdout = ioDiscard{}
	cmd.Stderr = &stderr
	if passphrase != "" {
		cmd.Stdin = strings.NewReader(passphrase + "\n")
	}
	if err := cmd.Run(); err != nil {
		s := strings.TrimSpace(stderr.String())
		if strings.Contains(strings.ToLower(s), "could not open a connection to your authentication agent") {
			return fmt.Errorf("ssh-agent not available. Run: eval $(ssh-agent -s)")
		}
		if strings.Contains(strings.ToLower(s), "bad passphrase") || strings.Contains(strings.ToLower(s), "incorrect passphrase") {
			return fmt.Errorf("invalid SSH key passphrase")
		}
		return fmt.Errorf("ssh-add failed: %w (%s)", err, s)
	}
	return nil
}

type ioDiscard struct{}

func (ioDiscard) Write(p []byte) (n int, err error) { return len(p), nil }

func redact(s string) string {
	// Best-effort redaction for common secret patterns.
	replacements := []string{"passphrase", "password", "token", "private key", "BEGIN RSA PRIVATE KEY"}
	out := s
	for _, k := range replacements {
		out = strings.ReplaceAll(strings.ToLower(out), k, "[redacted]")
	}
	if len(out) > 350 {
		out = out[:350] + "..."
	}
	return out
}
