package config

import "testing"

func TestResolveProfile_DefaultSingle(t *testing.T) {
	cfg := &Config{Profiles: map[string]Profile{"one": {Host: "h", User: "u"}}}
	name, _, ok := cfg.ResolveProfile("")
	if !ok || name != "one" {
		t.Fatalf("unexpected resolve: ok=%v name=%q", ok, name)
	}
}

func TestResolveProfile_ByAlias(t *testing.T) {
	cfg := &Config{Profiles: map[string]Profile{
		"personal_europlanet": {Host: "h", User: "u", Aliases: []string{"prod", "production", "server de prod"}},
	}}
	name, _, ok := cfg.ResolveProfile("mi server de prod")
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
