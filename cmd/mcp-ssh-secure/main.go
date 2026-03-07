package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"time"

	"github.com/mnofresno/mcp-ssh-secure/internal/audit"
	"github.com/mnofresno/mcp-ssh-secure/internal/config"
	"github.com/mnofresno/mcp-ssh-secure/internal/sshutil"
)

type jsonrpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type jsonrpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *jsonrpcError   `json:"error,omitempty"`
}

type jsonrpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type tool struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
}

func main() {
	logger := log.New(os.Stderr, "mcp-ssh-secure: ", log.LstdFlags|log.LUTC)

	cfg, err := config.Load()
	if err != nil {
		logger.Fatalf("load config: %v", err)
	}

	auditor, err := audit.New(cfg.Audit.LogPath)
	if err != nil {
		logger.Fatalf("audit init: %v", err)
	}

	runner := sshutil.NewRunner(cfg, auditor)

	dec := json.NewDecoder(os.Stdin)
	enc := json.NewEncoder(os.Stdout)

	for {
		var req jsonrpcRequest
		if err := dec.Decode(&req); err != nil {
			if errors.Is(err, io.EOF) {
				return
			}
			logger.Printf("decode request: %v", err)
			return
		}

		resp := handleRequest(req, cfg, runner)
		if len(req.ID) == 0 {
			continue
		}

		if err := enc.Encode(resp); err != nil {
			logger.Printf("encode response: %v", err)
			return
		}
	}
}

func handleRequest(req jsonrpcRequest, cfg *config.Config, runner *sshutil.Runner) jsonrpcResponse {
	resp := jsonrpcResponse{JSONRPC: "2.0", ID: req.ID}

	switch req.Method {
	case "initialize":
		resp.Result = map[string]any{
			"protocolVersion": "2024-11-05",
			"capabilities": map[string]any{
				"tools": map[string]any{},
			},
			"serverInfo": map[string]any{
				"name":    "mcp-ssh-secure",
				"version": "0.1.0",
			},
		}
		return resp
	case "notifications/initialized":
		return resp
	case "tools/list":
		resp.Result = map[string]any{"tools": toolDefs()}
		return resp
	case "tools/call":
		result, err := handleToolCall(req.Params, cfg, runner)
		if err != nil {
			resp.Error = &jsonrpcError{Code: -32000, Message: err.Error()}
			return resp
		}
		resp.Result = map[string]any{"content": []map[string]any{{"type": "text", "text": result}}}
		return resp
	default:
		resp.Error = &jsonrpcError{Code: -32601, Message: "method not found"}
		return resp
	}
}

func toolDefs() []tool {
	return []tool{
		{
			Name:        "list_profiles",
			Description: "Lists available SSH profiles from the local secure config file.",
			InputSchema: map[string]any{"type": "object", "properties": map[string]any{}},
		},
		{
			Name:        "ensure_ssh_agent_key",
			Description: "Checks whether an SSH key requires a passphrase and adds it to ssh-agent. If passphrase is required, returns instructions to ask the user. profile is optional and resolved by alias/default.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"profile":    map[string]any{"type": "string"},
					"target":     map[string]any{"type": "string"},
					"server":     map[string]any{"type": "string"},
					"passphrase": map[string]any{"type": "string"},
				},
			},
		},
		{
			Name:        "run_ssh_command",
			Description: "Runs a remote command over SSH. profile is optional and resolved with relaxed matching (prod/production/etc.).",
			InputSchema: map[string]any{
				"type":     "object",
				"required": []string{"command"},
				"properties": map[string]any{
					"profile":      map[string]any{"type": "string"},
					"target":       map[string]any{"type": "string"},
					"server":       map[string]any{"type": "string"},
					"command":      map[string]any{"type": "string"},
					"timeout_sec":  map[string]any{"type": "integer", "minimum": 1},
					"allocate_tty": map[string]any{"type": "boolean"},
				},
			},
		},
		{
			Name:        "run_sudo_command",
			Description: "Runs a remote command using sudo -S. Requires confirm='YES'. profile is optional and resolved by alias/default.",
			InputSchema: map[string]any{
				"type":     "object",
				"required": []string{"command", "confirm"},
				"properties": map[string]any{
					"profile":       map[string]any{"type": "string"},
					"target":        map[string]any{"type": "string"},
					"server":        map[string]any{"type": "string"},
					"command":       map[string]any{"type": "string"},
					"confirm":       map[string]any{"type": "string", "enum": []string{"YES"}},
					"timeout_sec":   map[string]any{"type": "integer", "minimum": 1},
					"sudo_password": map[string]any{"type": "string"},
				},
			},
		},
		{
			Name:        "audit_tail",
			Description: "Returns the latest local audit lines (without secrets).",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"lines": map[string]any{"type": "integer", "minimum": 1, "maximum": 200},
				},
			},
		},
	}
}

func handleToolCall(raw json.RawMessage, cfg *config.Config, runner *sshutil.Runner) (string, error) {
	var payload struct {
		Name      string                 `json:"name"`
		Arguments map[string]interface{} `json:"arguments"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return "", fmt.Errorf("invalid tools/call params: %w", err)
	}

	switch payload.Name {
	case "list_profiles":
		profiles := make([]string, 0, len(cfg.Profiles))
		for name := range cfg.Profiles {
			profiles = append(profiles, name)
		}
		return strings.Join(profiles, "\n"), nil
	case "ensure_ssh_agent_key":
		profile, _, ok := resolveProfileFromArgs(cfg, payload.Arguments)
		if !ok {
			return "", errors.New("could not resolve profile from profile/target/server. Configure a default profile or provide a hint like 'prod'")
		}
		passphrase, _ := strArg(payload.Arguments, "passphrase")
		out, err := runner.EnsureKey(context.Background(), profile, passphrase)
		if err != nil {
			return "", err
		}
		return out, nil
	case "run_ssh_command":
		profile, resolvedBy, ok := resolveProfileFromArgs(cfg, payload.Arguments)
		if !ok {
			return "", errors.New("could not resolve profile from profile/target/server. Configure a default profile or provide a hint like 'prod'")
		}
		command, ok := strArg(payload.Arguments, "command")
		if !ok {
			return "", errors.New("missing command")
		}
		timeout := durationArg(payload.Arguments, "timeout_sec", 45*time.Second)
		allocateTTY := boolArg(payload.Arguments, "allocate_tty", false)
		out, err := runner.RunSSH(profile, command, timeout, allocateTTY)
		if err != nil {
			return out, err
		}
		return fmt.Sprintf("[%s:%s]\n%s", resolvedBy, profile, out), nil
	case "run_sudo_command":
		profile, resolvedBy, ok := resolveProfileFromArgs(cfg, payload.Arguments)
		if !ok {
			return "", errors.New("could not resolve profile from profile/target/server. Configure a default profile or provide a hint like 'prod'")
		}
		command, ok := strArg(payload.Arguments, "command")
		if !ok {
			return "", errors.New("missing command")
		}
		confirm, ok := strArg(payload.Arguments, "confirm")
		if !ok || confirm != "YES" {
			return "", errors.New("sudo command requires explicit confirm='YES'")
		}
		overridePassword, _ := strArg(payload.Arguments, "sudo_password")
		timeout := durationArg(payload.Arguments, "timeout_sec", 45*time.Second)
		out, err := runner.RunSudoSSH(profile, command, timeout, overridePassword)
		if err != nil {
			return out, err
		}
		return fmt.Sprintf("[%s:%s]\n%s", resolvedBy, profile, out), nil
	case "audit_tail":
		lines := intArg(payload.Arguments, "lines", 40)
		if lines < 1 {
			lines = 1
		}
		if lines > 200 {
			lines = 200
		}
		return runner.ReadAuditTail(lines)
	default:
		return "", fmt.Errorf("tool not found: %s", payload.Name)
	}
}

func resolveProfileFromArgs(cfg *config.Config, args map[string]interface{}) (profile string, resolvedBy string, ok bool) {
	if v, ok := strArg(args, "profile"); ok {
		if name, _, found := cfg.ResolveProfile(v); found {
			return name, "profile", true
		}
	}
	if v, ok := strArg(args, "target"); ok {
		if name, _, found := cfg.ResolveProfile(v); found {
			return name, "target", true
		}
	}
	if v, ok := strArg(args, "server"); ok {
		if name, _, found := cfg.ResolveProfile(v); found {
			return name, "server", true
		}
	}
	if name, _, found := cfg.ResolveProfile(""); found {
		return name, "default", true
	}
	return "", "", false
}

func strArg(args map[string]interface{}, key string) (string, bool) {
	v, ok := args[key]
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	return s, ok
}

func intArg(args map[string]interface{}, key string, d int) int {
	v, ok := args[key]
	if !ok {
		return d
	}
	f, ok := v.(float64)
	if !ok {
		return d
	}
	return int(f)
}

func boolArg(args map[string]interface{}, key string, d bool) bool {
	v, ok := args[key]
	if !ok {
		return d
	}
	b, ok := v.(bool)
	if !ok {
		return d
	}
	return b
}

func durationArg(args map[string]interface{}, key string, d time.Duration) time.Duration {
	sec := intArg(args, key, int(d.Seconds()))
	if sec < 1 {
		sec = 1
	}
	if sec > 600 {
		sec = 600
	}
	return time.Duration(sec) * time.Second
}
