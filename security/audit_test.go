package security

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestAuditLogWritesJSONLWith0600(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	a, err := NewFileAuditor(path, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("audit file must exist with 0600, got %v %v", info, err)
	}

	ev := Event{
		Action:    AuditReveal,
		RequestID: "req-1",
		Method:    "GET",
		URI:       "/",
		Spans: []Snapshot{
			{Level: LevelSecret, RuleID: "builtin/header-authorization", Location: "header:Authorization", Fingerprint: "deadbeefdeadbeef"},
		},
	}
	if err := a.Log(ev); err != nil {
		t.Fatal(err)
	}
	if err := a.Log(Event{Action: AuditExport, RequestID: "req-1", Detail: "file: /tmp/x"}); err != nil {
		t.Fatal(err)
	}

	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	var lines []Event
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		var got Event
		if err := json.Unmarshal(scanner.Bytes(), &got); err != nil {
			t.Fatalf("audit line must be valid JSON: %v", err)
		}
		lines = append(lines, got)
	}
	if len(lines) != 2 {
		t.Fatalf("expected 2 audit records, got %d", len(lines))
	}
	if lines[0].Action != AuditReveal || lines[0].ExpiresAt.IsZero() {
		t.Errorf("event fields wrong: %+v", lines[0])
	}
	if lines[0].Spans[0].Fingerprint != "deadbeefdeadbeef" {
		t.Error("span snapshot must survive JSON encoding")
	}
}

func TestAuditSweepRemovesExpired(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	a, err := NewFileAuditor(path, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	a.now = func() time.Time { return now }

	// One fresh record, one expired record.
	if err := a.Log(Event{Action: AuditReveal}); err != nil {
		t.Fatal(err)
	}
	old := Event{
		Action:    AuditExport,
		Time:      now.Add(-48 * time.Hour),
		ExpiresAt: now.Add(-24 * time.Hour),
	}
	if err := a.Log(old); err != nil {
		t.Fatal(err)
	}

	removed, err := a.sweepLocked(now)
	if err != nil {
		t.Fatal(err)
	}
	if removed != 1 {
		t.Fatalf("expected 1 expired record removed, got %d", removed)
	}

	f, _ := os.Open(path)
	defer f.Close()
	scanner := bufio.NewScanner(f)
	var kept []Event
	for scanner.Scan() {
		var ev Event
		_ = json.Unmarshal(scanner.Bytes(), &ev)
		kept = append(kept, ev)
	}
	if len(kept) != 1 || kept[0].Action != AuditReveal {
		t.Fatalf("only the fresh record must remain, got %+v", kept)
	}
}

func TestAuditDefaultRetentionStampsExpiry(t *testing.T) {
	dir := t.TempDir()
	a, err := NewFileAuditor(filepath.Join(dir, "a.log"), 0)
	if err != nil {
		t.Fatal(err)
	}
	if a.Retention() != 7*24*time.Hour {
		t.Errorf("default retention = %v, want 7 days", a.Retention())
	}
}
