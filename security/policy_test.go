package security

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestJSONPathCompileAndMatch(t *testing.T) {
	cases := []struct {
		pattern string
		path    []PathSeg
		want    bool
	}{
		{"$.user.password", []PathSeg{{Kind: SegKey, Key: "user"}, {Kind: SegKey, Key: "password"}}, true},
		{"$.user.password", []PathSeg{{Kind: SegKey, Key: "user"}, {Kind: SegKey, Key: "name"}}, false},
		{"$['user'].password", []PathSeg{{Kind: SegKey, Key: "user"}, {Kind: SegKey, Key: "password"}}, true},
		{"$[0].token", []PathSeg{{Kind: SegIndex, Index: 0}, {Kind: SegKey, Key: "token"}}, true},
		{"$[*].token", []PathSeg{{Kind: SegIndex, Index: 9}, {Kind: SegKey, Key: "token"}}, true},
		{"$..password", []PathSeg{{Kind: SegKey, Key: "a"}, {Kind: SegKey, Key: "b"}, {Kind: SegKey, Key: "password"}}, true},
		{"$..password", []PathSeg{{Kind: SegKey, Key: "password"}}, true},
		{"$..password", []PathSeg{{Kind: SegKey, Key: "passphrase"}}, false},
		{"$.a.b", []PathSeg{{Kind: SegKey, Key: "a"}}, false},
		{"$", []PathSeg{}, true},
	}

	for _, tc := range cases {
		compiled, err := compileJSONPath(tc.pattern)
		if err != nil {
			t.Fatalf("compile %q: %v", tc.pattern, err)
		}
		if got := matchJSONPath(compiled, tc.path); got != tc.want {
			t.Errorf("pattern %q path %v: got %v want %v", tc.pattern, tc.path, got, tc.want)
		}
	}

	if _, err := compileJSONPath("user.password"); err == nil {
		t.Error("expected error for pattern without $ prefix")
	}
}

func TestDefaultPolicyMatches(t *testing.T) {
	p := NewDefaultPolicy()

	if r := p.MatchHeader("authorization"); r == nil || r.Level != LevelSecret {
		t.Errorf("authorization header must classify as secret, got %+v", r)
	}
	if r := p.MatchHeader("X-API-KEY"); r == nil {
		t.Error("X-API-KEY header should match case-insensitively")
	}
	if r := p.MatchFormField("PASSWORD"); r == nil {
		t.Error("form field match should be case-insensitive")
	}
	path := []PathSeg{{Kind: SegKey, Key: "payload"}, {Kind: SegKey, Key: "credit_card"}}
	if r := p.MatchJSONPath(path); r == nil || r.Level != LevelSecret {
		t.Errorf("credit_card jsonpath must classify, got %+v", r)
	}

	rules := p.RegexRules(ScopeHeaders)
	found := false
	for _, r := range rules {
		if r.ID == "builtin/regex-bearer" {
			found = true
		}
	}
	if !found {
		t.Error("bearer regex should apply to header scope")
	}
}

func TestRegexRuleFindAll(t *testing.T) {
	p := NewDefaultPolicy()
	text := []byte("token=abc123xyz other")
	var matched bool
	for _, r := range p.RegexRules(ScopeBody) {
		for _, m := range r.FindAllIndex(text) {
			if string(text[m[0]:m[1]]) == "token=abc123xyz" {
				matched = true
			}
		}
	}
	if !matched {
		t.Error("generic assignment regex should match token=...")
	}
}

func TestMergeAndMask(t *testing.T) {
	data := []byte("a=secret1; b=secret2")
	spans := []Span{
		{Start: 2, End: 9, Level: LevelSecret, RuleID: "r1"},
		{Start: 5, End: 9, Level: LevelConfidential, RuleID: "r2"}, // overlap, secret wins
		{Start: 13, End: 20, Level: LevelConfidential, RuleID: "r3"},
	}
	merged := MergeSpans(spans, len(data))
	if len(merged) != 2 {
		t.Fatalf("expected 2 merged spans, got %d: %+v", len(merged), merged)
	}
	if merged[0].Level != LevelSecret {
		t.Error("overlapping spans should keep highest level")
	}

	masked := ApplyMask(data, spans)
	out := string(masked)
	if strings.Contains(out, "secret1") || strings.Contains(out, "secret2") {
		t.Errorf("masked output leaked secrets: %q", out)
	}
	if !strings.Contains(out, MaskMarker(LevelSecret)) || !strings.Contains(out, MaskMarker(LevelConfidential)) {
		t.Errorf("masked output missing markers: %q", out)
	}
}

func TestMaskDoesNotMutateInput(t *testing.T) {
	data := []byte("password=hunter2")
	spans := []Span{{Start: 9, End: 16, Level: LevelSecret, RuleID: "r"}}
	masked := ApplyMask(data, spans)
	if string(data) != "password=hunter2" {
		t.Error("ApplyMask must not mutate the original bytes")
	}
	if string(masked) == string(data) {
		t.Error("expected masked output to differ")
	}
}

func TestLoadPolicyFileOverlay(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	content := `{
	  "mask_level": 3,
	  "reveal_ttl_seconds": 2,
	  "audit_retention_hours": 1,
	  "capture_retention_hours": 2,
	  "rules": [
	    {"id": "custom/x", "kind": "header", "pattern": "X-Trace-Token", "level": 2}
	  ]
	}`
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	p, err := LoadPolicyFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if p.MaskLevel != LevelSecret {
		t.Errorf("mask level overlay failed: %d", p.MaskLevel)
	}
	if p.RevealTTL != 2*time.Second {
		t.Errorf("reveal ttl overlay failed: %v", p.RevealTTL)
	}
	if p.AuditRetention != time.Hour {
		t.Errorf("audit retention overlay failed: %v", p.AuditRetention)
	}
	if p.CaptureRetention != 2*time.Hour {
		t.Errorf("capture retention overlay failed: %v", p.CaptureRetention)
	}
	if p.MatchHeader("X-Trace-Token") == nil {
		t.Error("custom header rule should be appended")
	}
	if p.MatchHeader("Authorization") == nil {
		t.Error("builtin rules should remain active")
	}

	// Missing file -> builtins, no error.
	p2, err := LoadPolicyFile(filepath.Join(dir, "nope.json"))
	if err != nil || p2 == nil {
		t.Fatalf("missing policy file must fall back to defaults: %v", err)
	}
}

func TestInvalidPolicyRuleRejected(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	content := `{"rules":[{"id":"bad","kind":"regex","pattern":"([","level":3}]}`
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPolicyFile(path); err == nil {
		t.Error("expected compile error for broken regexp rule")
	}
}

func TestSensitiveSpansThreshold(t *testing.T) {
	p := NewDefaultPolicy()
	p.MaskLevel = LevelSecret
	spans := []Span{
		{Start: 0, End: 1, Level: LevelConfidential},
		{Start: 1, End: 2, Level: LevelSecret},
	}
	got := p.SensitiveSpans(spans)
	if len(got) != 1 || got[0].Level != LevelSecret {
		t.Errorf("threshold filtering failed: %+v", got)
	}
}
