package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type Config struct {
	Profiles map[string]Profile `json:"profiles"`
	Audit    Audit              `json:"audit"`
}

type Audit struct {
	LogPath string `json:"log_path"`
}

type Profile struct {
	Host             string `json:"host"`
	Port             int    `json:"port"`
	User             string `json:"user"`
	KeyPath          string `json:"key_path,omitempty"`
	KnownHostsPath   string `json:"known_hosts_path,omitempty"`
	StrictHostKey    bool   `json:"strict_host_key_checking"`
	ConnectTimeoutS  int    `json:"connect_timeout_sec"`
	SudoPasswordFile string `json:"sudo_password_file,omitempty"`
	AuthMode         string `json:"auth_mode,omitempty"` // key|agent|password
	PasswordFile     string `json:"password_file,omitempty"`
}

func Load() (*Config, error) {
	p := os.Getenv("MCP_SSH_SECURE_CONFIG")
	if p == "" {
		h, _ := os.UserHomeDir()
		p = filepath.Join(h, ".config", "mcp-ssh-secure", "profiles.json")
	}

	b, err := os.ReadFile(p)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", p, err)
	}

	var cfg Config
	if err := json.Unmarshal(b, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	if len(cfg.Profiles) == 0 {
		return nil, fmt.Errorf("config has no profiles")
	}

	for name, prof := range cfg.Profiles {
		if prof.Host == "" || prof.User == "" {
			return nil, fmt.Errorf("profile %q requires host and user", name)
		}
		if prof.Port == 0 {
			prof.Port = 22
		}
		if prof.ConnectTimeoutS == 0 {
			prof.ConnectTimeoutS = 15
		}
		if prof.AuthMode == "" {
			if prof.PasswordFile != "" {
				prof.AuthMode = "password"
			} else if prof.KeyPath != "" {
				prof.AuthMode = "key"
			} else {
				prof.AuthMode = "agent"
			}
		}
		prof.AuthMode = strings.ToLower(prof.AuthMode)
		cfg.Profiles[name] = normalizeProfile(prof)
	}

	if cfg.Audit.LogPath == "" {
		h, _ := os.UserHomeDir()
		cfg.Audit.LogPath = filepath.Join(h, ".local", "state", "mcp-ssh-secure", "audit.log")
	}
	cfg.Audit.LogPath = expandHome(cfg.Audit.LogPath)

	return &cfg, nil
}

func (c *Config) Profile(name string) (Profile, bool) {
	p, ok := c.Profiles[name]
	return p, ok
}

func normalizeProfile(p Profile) Profile {
	p.KeyPath = expandHome(p.KeyPath)
	p.KnownHostsPath = expandHome(p.KnownHostsPath)
	p.SudoPasswordFile = expandHome(p.SudoPasswordFile)
	p.PasswordFile = expandHome(p.PasswordFile)
	return p
}

func expandHome(path string) string {
	if path == "" || !strings.HasPrefix(path, "~") {
		return path
	}
	h, _ := os.UserHomeDir()
	if path == "~" {
		return h
	}
	if strings.HasPrefix(path, "~/") {
		return filepath.Join(h, path[2:])
	}
	return path
}
