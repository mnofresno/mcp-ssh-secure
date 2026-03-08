package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

type Config struct {
	Profiles map[string]Profile `json:"profiles"`
	Audit    Audit              `json:"audit"`
}

type Audit struct {
	LogPath string `json:"log_path"`
}

type Profile struct {
	Host             string   `json:"host"`
	Port             int      `json:"port"`
	User             string   `json:"user"`
	KeyPath          string   `json:"key_path,omitempty"`
	KnownHostsPath   string   `json:"known_hosts_path,omitempty"`
	StrictHostKey    bool     `json:"strict_host_key_checking"`
	ForceIPv4        bool     `json:"force_ipv4,omitempty"`
	ConnectTimeoutS  int      `json:"connect_timeout_sec"`
	SudoPasswordFile string   `json:"sudo_password_file,omitempty"`
	AuthMode         string   `json:"auth_mode,omitempty"` // key|agent|password
	PasswordFile     string   `json:"password_file,omitempty"`
	Aliases          []string `json:"aliases,omitempty"`
	Default          bool     `json:"default,omitempty"`
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

func (c *Config) ResolveProfile(hint string) (string, Profile, bool) {
	if len(c.Profiles) == 0 {
		return "", Profile{}, false
	}

	if hint == "" {
		return c.resolveDefaultProfile()
	}

	q := normalizeQuery(hint)
	if q == "" {
		return c.resolveDefaultProfile()
	}

	// 1) Exact name match.
	for name, p := range c.Profiles {
		if normalizeQuery(name) == q {
			return name, p, true
		}
	}

	// 2) Exact alias match.
	for name, p := range c.Profiles {
		for _, a := range p.Aliases {
			if normalizeQuery(a) == q {
				return name, p, true
			}
		}
	}

	// 3) Heuristic contains match.
	type scored struct {
		name  string
		prof  Profile
		score int
	}
	var ranked []scored
	for name, p := range c.Profiles {
		score := 0
		normName := normalizeQuery(name)
		if strings.Contains(q, normName) || strings.Contains(normName, q) {
			score += 4
		}
		for _, a := range p.Aliases {
			na := normalizeQuery(a)
			if na == "" {
				continue
			}
			if strings.Contains(q, na) || strings.Contains(na, q) {
				score += 5
			}
		}
		if looksLikeProd(q) && profileLooksProd(name, p) {
			score += 8
		}
		if p.Default {
			score += 2
		}
		if score > 0 {
			ranked = append(ranked, scored{name: name, prof: p, score: score})
		}
	}
	if len(ranked) == 0 {
		return c.resolveDefaultProfile()
	}
	sort.Slice(ranked, func(i, j int) bool { return ranked[i].score > ranked[j].score })
	return ranked[0].name, ranked[0].prof, true
}

func normalizeProfile(p Profile) Profile {
	p.KeyPath = expandHome(p.KeyPath)
	p.KnownHostsPath = expandHome(p.KnownHostsPath)
	p.SudoPasswordFile = expandHome(p.SudoPasswordFile)
	p.PasswordFile = expandHome(p.PasswordFile)
	seen := make(map[string]struct{}, len(p.Aliases))
	out := make([]string, 0, len(p.Aliases))
	for _, a := range p.Aliases {
		a = strings.TrimSpace(a)
		if a == "" {
			continue
		}
		n := normalizeQuery(a)
		if _, ok := seen[n]; ok {
			continue
		}
		seen[n] = struct{}{}
		out = append(out, a)
	}
	p.Aliases = out
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

func (c *Config) resolveDefaultProfile() (string, Profile, bool) {
	for name, p := range c.Profiles {
		if p.Default {
			return name, p, true
		}
	}
	if len(c.Profiles) == 1 {
		for name, p := range c.Profiles {
			return name, p, true
		}
	}
	return "", Profile{}, false
}

func looksLikeProd(q string) bool {
	needles := []string{
		"prod", "production",
		"production server", "my production server",
		"live", "main server",
	}
	for _, n := range needles {
		if strings.Contains(q, normalizeQuery(n)) {
			return true
		}
	}
	return false
}

func profileLooksProd(name string, p Profile) bool {
	all := []string{name}
	all = append(all, p.Aliases...)
	for _, v := range all {
		n := normalizeQuery(v)
		if strings.Contains(n, "prod") || strings.Contains(n, "production") || strings.Contains(n, "live") {
			return true
		}
	}
	return false
}

func normalizeQuery(s string) string {
	s = strings.TrimSpace(strings.ToLower(stripAccents(s)))
	if s == "" {
		return ""
	}
	var b strings.Builder
	b.Grow(len(s))
	space := false
	for _, r := range s {
		if unicode.IsLetter(r) || unicode.IsNumber(r) {
			b.WriteRune(r)
			space = false
			continue
		}
		if !space {
			b.WriteRune(' ')
			space = true
		}
	}
	return strings.TrimSpace(b.String())
}

func stripAccents(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for len(s) > 0 {
		r, size := utf8.DecodeRuneInString(s)
		s = s[size:]
		switch r {
		case 'á', 'à', 'ä', 'â', 'ã':
			r = 'a'
		case 'é', 'è', 'ë', 'ê':
			r = 'e'
		case 'í', 'ì', 'ï', 'î':
			r = 'i'
		case 'ó', 'ò', 'ö', 'ô', 'õ':
			r = 'o'
		case 'ú', 'ù', 'ü', 'û':
			r = 'u'
		case 'ñ':
			r = 'n'
		}
		b.WriteRune(r)
	}
	return b.String()
}
