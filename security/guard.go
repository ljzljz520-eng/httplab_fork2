package security

import (
	"fmt"
	"time"
)

// Config wires the security Guard. Empty optional paths disable the
// corresponding feature.
type Config struct {
	// PolicyPath is loaded with built-in defaults when missing/empty.
	PolicyPath string
	// KeyPath stores the auto-generated KEK (ignored when MasterKey is set).
	KeyPath string
	// AuditPath is the JSONL audit log. Empty disables auditing.
	AuditPath string
	// CaptureDir is the managed encrypted capture store. Empty disables it.
	CaptureDir string
	// MasterKey overrides key-file resolution (raw or base64 32 bytes).
	MasterKey string

	// Optional overrides; zero values fall back to policy / defaults.
	RevealTTL        time.Duration
	AuditRetention   time.Duration
	CaptureRetention time.Duration
}

// Guard bundles every security subsystem behind one facade used by the UI.
type Guard struct {
	Policy *Policy
	Keys   *Keyring
	Tokens *Tokenizer
	Audit  *FileAuditor // nil when auditing is disabled
	Store  *Store       // nil when encrypted capture is disabled

	now    func() time.Time
	stopCh chan struct{}
}

// NewGuard builds the policy, keyring, auditor and capture store, and runs
// an initial retention sweep.
func NewGuard(cfg Config) (*Guard, error) {
	policy, err := LoadPolicyFile(cfg.PolicyPath)
	if err != nil {
		return nil, err
	}
	if cfg.RevealTTL > 0 {
		policy.RevealTTL = cfg.RevealTTL
	}
	if cfg.AuditRetention > 0 {
		policy.AuditRetention = cfg.AuditRetention
	}
	if cfg.CaptureRetention > 0 {
		policy.CaptureRetention = cfg.CaptureRetention
	}

	keys, err := LoadOrCreateKeyring(cfg.MasterKey, cfg.KeyPath)
	if err != nil {
		return nil, err
	}

	g := &Guard{
		Policy: policy,
		Keys:   keys,
		Tokens: keys.NewTokenizer(),
		now:    time.Now,
		stopCh: make(chan struct{}),
	}

	if cfg.AuditPath != "" {
		auditor, err := NewFileAuditor(cfg.AuditPath, policy.AuditRetention)
		if err != nil {
			return nil, err
		}
		g.Audit = auditor
	}

	if cfg.CaptureDir != "" {
		store, err := NewStore(cfg.CaptureDir, keys, policy.CaptureRetention)
		if err != nil {
			return nil, err
		}
		g.Store = store
	}

	if _, _, err := g.SweepNow(); err != nil {
		return nil, err
	}
	return g, nil
}

// Now returns the guard clock (override in tests).
func (g *Guard) Now() time.Time { return g.now() }

// RevealTTL returns the authorized-reveal window.
func (g *Guard) RevealTTL() time.Duration { return g.Policy.RevealTTL }

// Snapshots projects spans (relative to plain) into audit-safe snapshots.
func (g *Guard) Snapshots(plain []byte, spans []Span) []Snapshot {
	merged := MergeSpans(spans, len(plain))
	snaps := make([]Snapshot, 0, len(merged))
	for _, s := range merged {
		snaps = append(snaps, Snapshot{
			Level:       s.Level,
			RuleID:      s.RuleID,
			Kind:        s.Kind,
			Location:    s.Location,
			Fingerprint: Fingerprint(plain[s.Start:s.End]),
		})
	}
	return snaps
}

// RecordEvent is a convenience that drops the event when auditing is off.
func (g *Guard) RecordEvent(ev Event) {
	if g.Audit == nil {
		return
	}
	_ = g.Audit.Log(ev)
}

// SweepNow enforces retention on the audit log and the capture store.
func (g *Guard) SweepNow() (auditRemoved, captureRemoved int, err error) {
	if g.Audit != nil {
		auditRemoved, err = g.Audit.Sweep()
		if err != nil {
			return 0, 0, err
		}
	}
	if g.Store != nil {
		captureRemoved, err = g.Store.Sweep()
		if err != nil {
			return auditRemoved, 0, err
		}
	}
	if auditRemoved > 0 || captureRemoved > 0 {
		g.RecordEvent(Event{
			Action: AuditSweep,
			Detail: fmt.Sprintf("removed %d expired audit records, %d expired encrypted captures",
				auditRemoved, captureRemoved),
		})
	}
	return auditRemoved, captureRemoved, nil
}

// StartMaintenance periodically enforces retention until Close.
func (g *Guard) StartMaintenance(interval time.Duration) {
	if interval <= 0 {
		interval = time.Hour
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				_, _, _ = g.SweepNow()
			case <-g.stopCh:
				return
			}
		}
	}()
}

// Close stops the maintenance loop.
func (g *Guard) Close() {
	select {
	case <-g.stopCh:
	default:
		close(g.stopCh)
	}
}
