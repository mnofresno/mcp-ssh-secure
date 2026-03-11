package main

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mnofresno/mcp-ssh-secure/internal/audit"
	"github.com/mnofresno/mcp-ssh-secure/internal/config"
	"github.com/mnofresno/mcp-ssh-secure/internal/sshutil"
)

func testRunner(t *testing.T, cfg *config.Config) *sshutil.Runner {
	t.Helper()
	auditor, err := audit.New(filepath.Join(t.TempDir(), "audit.log"))
	if err != nil {
		t.Fatalf("audit.New() error = %v", err)
	}
	return sshutil.NewRunner(cfg, auditor)
}

func TestHandleRequestInitializeAndMethodNotFound(t *testing.T) {
	cfg := &config.Config{Profiles: map[string]config.Profile{"prod": {Host: "h", User: "u"}}}
	runner := testRunner(t, cfg)

	initResp := handleRequest(jsonrpcRequest{JSONRPC: "2.0", ID: json.RawMessage("1"), Method: "initialize"}, cfg, runner)
	if initResp.Error != nil {
		t.Fatalf("initialize returned error: %+v", initResp.Error)
	}
	result, ok := initResp.Result.(map[string]any)
	if !ok || result["protocolVersion"] != "2024-11-05" {
		t.Fatalf("unexpected initialize result: %#v", initResp.Result)
	}

	miss := handleRequest(jsonrpcRequest{JSONRPC: "2.0", ID: json.RawMessage("2"), Method: "missing"}, cfg, runner)
	if miss.Error == nil || miss.Error.Code != -32601 {
		t.Fatalf("unexpected method-not-found response: %+v", miss.Error)
	}
}

func TestToolDefsIncludeSudoPasswordInput(t *testing.T) {
	var found bool
	for _, def := range toolDefs() {
		if def.Name != "run_sudo_command" {
			continue
		}
		found = true
		props := def.InputSchema["properties"].(map[string]any)
		if _, ok := props["sudo_password"]; !ok {
			t.Fatal("run_sudo_command is missing sudo_password input")
		}
	}
	if !found {
		t.Fatal("run_sudo_command tool definition not found")
	}
}

func TestHandleToolCallListProfilesAndAuditTail(t *testing.T) {
	cfg := &config.Config{
		Profiles: map[string]config.Profile{
			"prod": {Host: "h", User: "u", Default: true},
			"dev":  {Host: "h", User: "u"},
		},
	}
	runner := testRunner(t, cfg)
	runner.EnsureKey(context.Background(), "missing", "")

	rawList := json.RawMessage(`{"name":"list_profiles","arguments":{}}`)
	listOut, err := handleToolCall(rawList, cfg, runner)
	if err != nil {
		t.Fatalf("list_profiles error = %v", err)
	}
	if !strings.Contains(listOut, "prod") || !strings.Contains(listOut, "dev") {
		t.Fatalf("unexpected profile list: %s", listOut)
	}

	rawTail := json.RawMessage(`{"name":"audit_tail","arguments":{"lines":999}}`)
	tailOut, err := handleToolCall(rawTail, cfg, runner)
	if err != nil {
		t.Fatalf("audit_tail error = %v", err)
	}
	if strings.Contains(strings.ToLower(tailOut), "password") {
		t.Fatalf("audit_tail leaked a secret: %s", tailOut)
	}
}

func TestHandleToolCallRunSudoRequiresExplicitConfirm(t *testing.T) {
	cfg := &config.Config{Profiles: map[string]config.Profile{
		"prod": {Host: "h", User: "u", Default: true},
	}}
	runner := testRunner(t, cfg)

	raw := json.RawMessage(`{"name":"run_sudo_command","arguments":{"command":"id","confirm":"NO","sudo_password":"super-secret"}}`)
	_, err := handleToolCall(raw, cfg, runner)
	if err == nil {
		t.Fatal("expected run_sudo_command to reject missing confirmation")
	}
	msg := err.Error()
	if !strings.Contains(msg, "confirm='YES'") {
		t.Fatalf("unexpected error: %s", msg)
	}
	if strings.Contains(msg, "super-secret") {
		t.Fatalf("error leaked password: %s", msg)
	}
}

func TestResolveProfileFromArgsAndHelpers(t *testing.T) {
	cfg := &config.Config{Profiles: map[string]config.Profile{
		"prod-main": {Host: "h", User: "u", Aliases: []string{"production"}, Default: true},
		"dev":       {Host: "h", User: "u", Aliases: []string{"sandbox"}},
	}}

	if name, by, ok := resolveProfileFromArgs(cfg, map[string]interface{}{"target": "production"}); !ok || name != "prod-main" || by != "target" {
		t.Fatalf("unexpected target resolution: ok=%v name=%q by=%q", ok, name, by)
	}
	if name, by, ok := resolveProfileFromArgs(cfg, map[string]interface{}{"server": "sandbox"}); !ok || name != "dev" || by != "server" {
		t.Fatalf("unexpected server resolution: ok=%v name=%q by=%q", ok, name, by)
	}
	if name, by, ok := resolveProfileFromArgs(cfg, map[string]interface{}{}); !ok || name != "prod-main" || by != "default" {
		t.Fatalf("unexpected default resolution: ok=%v name=%q by=%q", ok, name, by)
	}

	args := map[string]interface{}{
		"str":      "x",
		"int":      float64(700),
		"bool":     true,
		"bad_int":  "7",
		"bad_bool": "true",
	}
	if v, ok := strArg(args, "str"); !ok || v != "x" {
		t.Fatalf("unexpected strArg result: ok=%v value=%q", ok, v)
	}
	if got := intArg(args, "int", 5); got != 700 {
		t.Fatalf("unexpected intArg result: %d", got)
	}
	if got := intArg(args, "bad_int", 5); got != 5 {
		t.Fatalf("unexpected intArg default result: %d", got)
	}
	if got := boolArg(args, "bool", false); !got {
		t.Fatal("unexpected boolArg result: false")
	}
	if got := boolArg(args, "bad_bool", false); got {
		t.Fatal("unexpected boolArg fallback result: true")
	}
	if got := durationArg(args, "int", 45*time.Second); got != 600*time.Second {
		t.Fatalf("expected capped duration, got %s", got)
	}
	if got := durationArg(map[string]interface{}{"timeout_sec": float64(0)}, "timeout_sec", 45*time.Second); got != time.Second {
		t.Fatalf("expected minimum duration, got %s", got)
	}
}
