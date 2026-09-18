// Package security implements sensitive-data classification, masking,
// envelope encryption, irreversible tokenization and auditing for httplab.
//
// The package only depends on the Go standard library so it keeps building
// under the project's vendored, GOPATH-based workflow.
package security

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"
)

// Level is the sensitivity grade assigned to a classified span.
type Level int

const (
	// LevelLow is non sensitive data, never masked.
	LevelLow Level = 1
	// LevelConfidential is masked by default (e.g. session tokens).
	LevelConfidential Level = 2
	// LevelSecret is the most sensitive grade (credentials, private keys).
	LevelSecret Level = 3
)

// String renders the level for audit records / UI hints.
func (l Level) String() string {
	switch l {
	case LevelSecret:
		return "secret"
	case LevelConfidential:
		return "confidential"
	default:
		return "low"
	}
}

// Span describes a sensitive byte range inside a captured request.
// Offsets always refer to the *plain* (color stripped) render produced by
// the capture pipeline.
type Span struct {
	Start    int    `json:"-"`
	End      int    `json:"-"`
	Level    Level  `json:"level"`
	RuleID   string `json:"rule"`
	Kind     string `json:"kind"`
	Location string `json:"location"`
}

// Snapshot is the audit-safe projection of a span: it never carries the
// original value, only a non reversible fingerprint of it.
type Snapshot struct {
	Level       Level  `json:"level"`
	RuleID      string `json:"rule"`
	Kind        string `json:"kind"`
	Location    string `json:"location"`
	Fingerprint string `json:"fingerprint"`
}

// Rule kinds.
const (
	KindHeader   = "header"
	KindJSONPath = "jsonpath"
	KindForm     = "form"
	KindRegex    = "regex"
)

// Regex scopes. Empty / ScopeAll means both headers (incl. request line)
// and bodies.
const (
	ScopeAll     = "all"
	ScopeHeaders = "headers"
	ScopeBody    = "body"
)

// Rule is a single classification rule.
//
//   - kind "header":    Pattern is a header name, matched case-insensitively
//   - kind "jsonpath":  Pattern is a JSONPath subset ($.a.b, $[0], [*], $..k)
//   - kind "form":      Pattern is a form field / query parameter name
//   - kind "regex":     Pattern is a Go regexp scanned over values/text
type Rule struct {
	ID      string `json:"id"`
	Kind    string `json:"kind"`
	Pattern string `json:"pattern"`
	Level   Level  `json:"level"`
	Scope   string `json:"scope,omitempty"`

	re       *regexp.Regexp
	pathSegs []PathSeg
}

func (r *Rule) compile() error {
	if r.Level == 0 {
		r.Level = LevelConfidential
	}
	switch r.Kind {
	case KindHeader, KindForm:
		r.Pattern = strings.TrimSpace(r.Pattern)
	case KindJSONPath:
		segs, err := compileJSONPath(r.Pattern)
		if err != nil {
			return fmt.Errorf("rule %q: %v", r.ID, err)
		}
		r.pathSegs = segs
	case KindRegex:
		re, err := regexp.Compile(r.Pattern)
		if err != nil {
			return fmt.Errorf("rule %q: %v", r.ID, err)
		}
		r.re = re
		if r.Scope == "" {
			r.Scope = ScopeAll
		}
	default:
		return fmt.Errorf("rule %q: unknown kind %q", r.ID, r.Kind)
	}
	if r.ID == "" {
		return fmt.Errorf("rule without id: %s %q", r.Kind, r.Pattern)
	}
	return nil
}

// Policy is the resolved classification policy plus data-handling settings.
type Policy struct {
	Rules []*Rule

	// Levels >= MaskLevel are replaced when rendering (default LevelConfidential).
	MaskLevel Level

	RevealTTL        time.Duration
	AuditRetention   time.Duration
	CaptureRetention time.Duration
}

// NewDefaultPolicy returns the built-in policy.
func NewDefaultPolicy() *Policy {
	p := &Policy{
		MaskLevel:        LevelConfidential,
		RevealTTL:        15 * time.Second,
		AuditRetention:   7 * 24 * time.Hour,
		CaptureRetention: 24 * time.Hour,
	}
	for _, r := range builtinRules {
		cp := r
		if err := cp.compile(); err == nil {
			p.Rules = append(p.Rules, &cp)
		}
	}
	return p
}

// builtinRules are always active; user rules are appended and win ties by
// being evaluated later.
var builtinRules = []Rule{
	// --- Headers -------------------------------------------------------
	{ID: "builtin/header-authorization", Kind: KindHeader, Pattern: "Authorization", Level: LevelSecret},
	{ID: "builtin/header-proxy-authorization", Kind: KindHeader, Pattern: "Proxy-Authorization", Level: LevelSecret},
	{ID: "builtin/header-cookie", Kind: KindHeader, Pattern: "Cookie", Level: LevelSecret},
	{ID: "builtin/header-set-cookie", Kind: KindHeader, Pattern: "Set-Cookie", Level: LevelSecret},
	{ID: "builtin/header-x-api-key", Kind: KindHeader, Pattern: "X-Api-Key", Level: LevelSecret},
	{ID: "builtin/header-api-key", Kind: KindHeader, Pattern: "Api-Key", Level: LevelSecret},
	{ID: "builtin/header-x-auth-token", Kind: KindHeader, Pattern: "X-Auth-Token", Level: LevelSecret},
	{ID: "builtin/header-x-access-token", Kind: KindHeader, Pattern: "X-Access-Token", Level: LevelSecret},

	// --- JSON paths (recursive, match at any depth) --------------------
	{ID: "builtin/json-password", Kind: KindJSONPath, Pattern: "$..password", Level: LevelSecret},
	{ID: "builtin/json-passwd", Kind: KindJSONPath, Pattern: "$..passwd", Level: LevelSecret},
	{ID: "builtin/json-pwd", Kind: KindJSONPath, Pattern: "$..pwd", Level: LevelSecret},
	{ID: "builtin/json-secret", Kind: KindJSONPath, Pattern: "$..secret", Level: LevelSecret},
	{ID: "builtin/json-client-secret", Kind: KindJSONPath, Pattern: "$..client_secret", Level: LevelSecret},
	{ID: "builtin/json-token", Kind: KindJSONPath, Pattern: "$..token", Level: LevelSecret},
	{ID: "builtin/json-access-token", Kind: KindJSONPath, Pattern: "$..access_token", Level: LevelSecret},
	{ID: "builtin/json-refresh-token", Kind: KindJSONPath, Pattern: "$..refresh_token", Level: LevelSecret},
	{ID: "builtin/json-api-key", Kind: KindJSONPath, Pattern: "$..api_key", Level: LevelSecret},
	{ID: "builtin/json-apikey", Kind: KindJSONPath, Pattern: "$..apiKey", Level: LevelSecret},
	{ID: "builtin/json-authorization", Kind: KindJSONPath, Pattern: "$..authorization", Level: LevelSecret},
	{ID: "builtin/json-card-number", Kind: KindJSONPath, Pattern: "$..card_number", Level: LevelSecret},
	{ID: "builtin/json-credit-card", Kind: KindJSONPath, Pattern: "$..credit_card", Level: LevelSecret},
	{ID: "builtin/json-cvv", Kind: KindJSONPath, Pattern: "$..cvv", Level: LevelSecret},
	{ID: "builtin/json-ssn", Kind: KindJSONPath, Pattern: "$..ssn", Level: LevelSecret},

	// --- Form / query fields ------------------------------------------
	{ID: "builtin/form-password", Kind: KindForm, Pattern: "password", Level: LevelSecret},
	{ID: "builtin/form-passwd", Kind: KindForm, Pattern: "passwd", Level: LevelSecret},
	{ID: "builtin/form-pwd", Kind: KindForm, Pattern: "pwd", Level: LevelSecret},
	{ID: "builtin/form-secret", Kind: KindForm, Pattern: "secret", Level: LevelSecret},
	{ID: "builtin/form-token", Kind: KindForm, Pattern: "token", Level: LevelSecret},
	{ID: "builtin/form-access-token", Kind: KindForm, Pattern: "access_token", Level: LevelSecret},
	{ID: "builtin/form-refresh-token", Kind: KindForm, Pattern: "refresh_token", Level: LevelSecret},
	{ID: "builtin/form-api-key", Kind: KindForm, Pattern: "api_key", Level: LevelSecret},
	{ID: "builtin/form-apikey", Kind: KindForm, Pattern: "apikey", Level: LevelSecret},
	{ID: "builtin/form-card-number", Kind: KindForm, Pattern: "card_number", Level: LevelSecret},
	{ID: "builtin/form-cvv", Kind: KindForm, Pattern: "cvv", Level: LevelSecret},
	{ID: "builtin/form-ssn", Kind: KindForm, Pattern: "ssn", Level: LevelSecret},
	{ID: "builtin/form-authorization", Kind: KindForm, Pattern: "authorization", Level: LevelSecret},

	// --- Regexes, anywhere --------------------------------------------
	// Credential *patterns* (Bearer, JWT, provider key formats) are scanned
	// in headers, request lines and bodies. The generic "key=value" rule is
	// body-only: headers are classified structurally, otherwise its match
	// would swallow the "Header-Name: " prefix of a known header.
	{ID: "builtin/regex-bearer", Kind: KindRegex, Pattern: `Bearer [A-Za-z0-9._~+\-/=]{8,}`, Level: LevelSecret, Scope: ScopeAll},
	{ID: "builtin/regex-jwt", Kind: KindRegex, Pattern: `eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}`, Level: LevelSecret, Scope: ScopeAll},
	{ID: "builtin/regex-aws-access-key", Kind: KindRegex, Pattern: `AKIA[0-9A-Z]{16}`, Level: LevelSecret, Scope: ScopeAll},
	{ID: "builtin/regex-openai", Kind: KindRegex, Pattern: `sk-[A-Za-z0-9]{20,}`, Level: LevelSecret, Scope: ScopeAll},
	{ID: "builtin/regex-github-token", Kind: KindRegex, Pattern: `gh[pousr]_[A-Za-z0-9]{36,}`, Level: LevelSecret, Scope: ScopeAll},
	{ID: "builtin/regex-slack-token", Kind: KindRegex, Pattern: `xox[baprs]-[A-Za-z0-9-]{10,}`, Level: LevelSecret, Scope: ScopeAll},
	{ID: "builtin/regex-google-api", Kind: KindRegex, Pattern: `AIza[0-9A-Za-z\-_]{35}`, Level: LevelSecret, Scope: ScopeAll},
	{ID: "builtin/regex-generic-assignment", Kind: KindRegex, Pattern: `(?i)(password|passwd|secret|api[_-]?key|token|authorization)\s*[=:]\s*["']?[^\s"'&,;]{3,}`, Level: LevelConfidential, Scope: ScopeBody},
}

// policyFile is the on-disk JSON representation.
type policyFile struct {
	MaskLevel             Level   `json:"mask_level"`
	RevealTTLSeconds      int     `json:"reveal_ttl_seconds"`
	AuditRetentionHours   float64 `json:"audit_retention_hours"`
	CaptureRetentionHours float64 `json:"capture_retention_hours"`
	Rules                 []Rule  `json:"rules"`
}

// LoadPolicyFile loads a user policy file, layering it over the built-in
// policy. A missing file is not an error: the built-in policy is returned.
func LoadPolicyFile(path string) (*Policy, error) {
	if path == "" {
		return NewDefaultPolicy(), nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return NewDefaultPolicy(), nil
		}
		return nil, err
	}

	var pf policyFile
	if err := json.Unmarshal(data, &pf); err != nil {
		return nil, fmt.Errorf("parse policy %q: %v", path, err)
	}

	p := NewDefaultPolicy()
	if pf.MaskLevel >= LevelLow && pf.MaskLevel <= LevelSecret {
		p.MaskLevel = pf.MaskLevel
	}
	if pf.RevealTTLSeconds > 0 {
		p.RevealTTL = time.Duration(pf.RevealTTLSeconds) * time.Second
	}
	if pf.AuditRetentionHours > 0 {
		p.AuditRetention = durationFromHours(pf.AuditRetentionHours)
	}
	if pf.CaptureRetentionHours > 0 {
		p.CaptureRetention = durationFromHours(pf.CaptureRetentionHours)
	}

	for i := range pf.Rules {
		r := pf.Rules[i]
		if err := r.compile(); err != nil {
			return nil, err
		}
		p.Rules = append(p.Rules, &r)
	}
	return p, nil
}

func durationFromHours(h float64) time.Duration {
	return time.Duration(h * float64(time.Hour))
}

// MatchHeader returns the rule matching a header name, or nil.
func (p *Policy) MatchHeader(name string) *Rule {
	for _, r := range p.Rules {
		if r.Kind == KindHeader && strings.EqualFold(r.Pattern, name) {
			return r
		}
	}
	return nil
}

// MatchFormField returns the rule matching a form/query field name, or nil.
// Matching is case-insensitive.
func (p *Policy) MatchFormField(name string) *Rule {
	for _, r := range p.Rules {
		if r.Kind == KindForm && strings.EqualFold(r.Pattern, name) {
			return r
		}
	}
	return nil
}

// MatchJSONPath matches a concrete path such as $.user.password.
func (p *Policy) MatchJSONPath(path []PathSeg) *Rule {
	for _, r := range p.Rules {
		if r.Kind == KindJSONPath && matchJSONPath(r.pathSegs, path) {
			return r
		}
	}
	return nil
}

// RegexRules returns regex rules applicable to the given scope
// (ScopeHeaders / ScopeBody).
func (p *Policy) RegexRules(scope string) []*Rule {
	var out []*Rule
	for _, r := range p.Rules {
		if r.Kind != KindRegex {
			continue
		}
		if r.Scope == ScopeAll || r.Scope == scope {
			out = append(out, r)
		}
	}
	return out
}

// FindAllIndex exposes the compiled regexp matches for regex rules.
func (r *Rule) FindAllIndex(text []byte) [][]int {
	if r.re == nil {
		return nil
	}
	return r.re.FindAllIndex(text, -1)
}

// IsMasked reports whether a span must be masked under this policy.
func (p *Policy) IsMasked(s Span) bool {
	return s.Level >= p.MaskLevel
}

// SensitiveSpans keeps only the spans at or above MaskLevel.
func (p *Policy) SensitiveSpans(spans []Span) []Span {
	out := spans[:0:0]
	for _, s := range spans {
		if p.IsMasked(s) {
			out = append(out, s)
		}
	}
	return out
}
