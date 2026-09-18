package security

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newTestGuard(t *testing.T, captureEnabled bool) (*Guard, string) {
	t.Helper()
	dir := t.TempDir()

	master := make([]byte, 32)
	for i := range master {
		master[i] = byte(i + 1)
	}

	cfg := Config{
		PolicyPath:     filepath.Join(dir, "missing-policy.json"),
		KeyPath:        filepath.Join(dir, "master.key"),
		AuditPath:      filepath.Join(dir, "audit.log"),
		MasterKey:      base64.StdEncoding.EncodeToString(master),
		RevealTTL:      5 * time.Second,
		AuditRetention: time.Hour,
	}
	if captureEnabled {
		cfg.CaptureDir = filepath.Join(dir, "caps")
		cfg.CaptureRetention = time.Hour
	}

	g, err := NewGuard(cfg)
	if err != nil {
		t.Fatalf("NewGuard: %v", err)
	}
	return g, dir
}

func TestGuardSnapshotsNeverContainValues(t *testing.T) {
	g, _ := newTestGuard(t, false)
	defer g.Close()

	plain := []byte("Authorization: Bearer abcdefgh12345678")
	spans := []Span{{Start: 15, End: 38, Level: LevelSecret, RuleID: "r", Kind: KindHeader, Location: "header:Authorization"}}

	snaps := g.Snapshots(plain, spans)
	if len(snaps) != 1 {
		t.Fatalf("expected 1 snapshot, got %d", len(snaps))
	}
	if snaps[0].Fingerprint == "" || strings.Contains(snaps[0].Fingerprint, "abcdefgh") {
		t.Errorf("snapshot must carry only a fingerprint, got %+v", snaps[0])
	}
	if snaps[0].Location != "header:Authorization" {
		t.Errorf("location lost: %+v", snaps[0])
	}
}

func TestGuardRecordsAndSweepsAudit(t *testing.T) {
	g, dir := newTestGuard(t, true)
	defer g.Close()

	if g.Store == nil {
		t.Error("capture store should be enabled")
	}
	if g.RevealTTL() != 5*time.Second {
		t.Errorf("reveal ttl override failed: %v", g.RevealTTL())
	}

	g.RecordEvent(Event{Action: AuditReveal, RequestID: "req-1"})
	g.RecordEvent(Event{Action: AuditExport, RequestID: "req-1", Detail: "file: /tmp/x"})

	blob, err := os.ReadFile(filepath.Join(dir, "audit.log"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(blob), AuditReveal) || !strings.Contains(string(blob), AuditExport) {
		t.Errorf("audit log missing events:\n%s", blob)
	}

	// Persist + encrypted store roundtrip through the guard.
	path, err := g.Store.Persist(Record{ID: "req-1", Plain: []byte("GET / HTTP/1.1\nX-Api-Key: k-1234567890")})
	if err != nil {
		t.Fatal(err)
	}
	enc, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(enc), "k-1234567890") {
		t.Error("capture store must encrypt data at rest")
	}
	plain, err := g.Keys.Open(enc)
	if err != nil || !strings.Contains(string(plain), "k-1234567890") {
		t.Fatalf("guard keyring must open its own captures: %q %v", plain, err)
	}
}

func TestGuardWithoutOptionalPaths(t *testing.T) {
	g, err := NewGuard(Config{
		MasterKey: base64.StdEncoding.EncodeToString(make([]byte, 32)),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	if g.Audit != nil || g.Store != nil {
		t.Error("audit and store must be nil with empty paths")
	}
	// Must not panic with auditing disabled.
	g.RecordEvent(Event{Action: AuditReveal})
	if _, _, err := g.SweepNow(); err != nil {
		t.Errorf("sweep without sinks must be a noop without error: %v", err)
	}
}
