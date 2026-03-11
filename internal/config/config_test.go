package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveProfile_DefaultSingle(t *testing.T) {
	cfg := &Config{Profiles: map[string]Profile{"one": {Host: "h", User: "u"}}}
	name, _, ok := cfg.ResolveProfile("")
	if !ok || name != "one" {
		t.Fatalf("unexpected resolve: ok=%v name=%q", ok, name)
	}
}

func TestResolveProfile_ByAlias(t *testing.T) {
	cfg := &Config{Profiles: map[string]Profile{
		"personal_europlanet": {Host: "h", User: "u", Aliases: []string{"prod", "production", "production server"}},
	}}
	name, _, ok := cfg.ResolveProfile("my production server")
	if !ok || name != "personal_europlanet" {
		t.Fatalf("unexpected resolve: ok=%v name=%q", ok, name)
	}
}

func TestResolveProfile_DefaultFlag(t *testing.T) {
	cfg := &Config{Profiles: map[string]Profile{
		"a": {Host: "h", User: "u"},
		"b": {Host: "h", User: "u", Default: true},
	}}
	name, _, ok := cfg.ResolveProfile("")
	if !ok || name != "b" {
		t.Fatalf("unexpected resolve: ok=%v name=%q", ok, name)
	}
}

func TestLoadAppliesDefaultsAndExpandsHome(t *testing.T) {
	tmp := t.TempDir()
	home := filepath.Join(tmp, "home")
	if err := os.MkdirAll(home, 0o755); err != nil {
		t.Fatalf("mkdir home: %v", err)
	}

	configPath := filepath.Join(tmp, "profiles.json")
	raw := `{
		"profiles": {
			"prod": {
				"host": "example.com",
				"user": "alice",
				"key_path": "~/id_ed25519",
				"known_hosts_path": "~/known_hosts",
				"sudo_password_file": "~/sudo.txt",
				"aliases": [" prod ", "prod", ""]
			}
		}
	}`
	if err := os.WriteFile(configPath, []byte(raw), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	t.Setenv("MCP_SSH_SECURE_CONFIG", configPath)
	t.Setenv("HOME", home)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	prof, ok := cfg.Profile("prod")
	if !ok {
		t.Fatal("missing loaded profile")
	}
	if prof.Port != 22 || prof.ConnectTimeoutS != 15 || prof.AuthMode != "key" {
		t.Fatalf("unexpected defaults: %+v", prof)
	}
	if prof.KeyPath != filepath.Join(home, "id_ed25519") {
		t.Fatalf("key path not expanded: %s", prof.KeyPath)
	}
	if prof.KnownHostsPath != filepath.Join(home, "known_hosts") {
		t.Fatalf("known_hosts path not expanded: %s", prof.KnownHostsPath)
	}
	if prof.SudoPasswordFile != filepath.Join(home, "sudo.txt") {
		t.Fatalf("sudo password path not expanded: %s", prof.SudoPasswordFile)
	}
	if len(prof.Aliases) != 1 || prof.Aliases[0] != "prod" {
		t.Fatalf("aliases not normalized: %#v", prof.Aliases)
	}
	if cfg.Audit.LogPath != filepath.Join(home, ".local", "state", "mcp-ssh-secure", "audit.log") {
		t.Fatalf("unexpected audit path: %s", cfg.Audit.LogPath)
	}
}
