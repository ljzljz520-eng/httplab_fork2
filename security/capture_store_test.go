package security

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCaptureStorePersistsEncrypted(t *testing.T) {
	dir := t.TempDir()
	ring := newTestKeyring(t)
	store, err := NewStore(filepath.Join(dir, "caps"), ring, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	rec := Record{
		ID:         "req-7",
		Method:     "POST",
		URI:        "/login",
		ReceivedAt: time.Now().UTC(),
		Plain:      []byte("Authorization: Bearer abcdefgh12345678\npassword=hunter2"),
	}
	path, err := store.Persist(rec)
	if err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("capture perm = %o, want 0600", info.Mode().Perm())
	}

	blob, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(blob), "abcdefgh12345678") || strings.Contains(string(blob), "hunter2") {
		t.Error("encrypted capture file must not contain plaintext secrets")
	}

	plain, err := ring.Open(blob)
	if err != nil {
		t.Fatal(err)
	}
	if string(plain) != string(rec.Plain) {
		t.Error("encrypted capture must open back to the original plain")
	}
}

func TestCaptureStoreSweep(t *testing.T) {
	dir := t.TempDir()
	ring := newTestKeyring(t)
	store, err := NewStore(filepath.Join(dir, "caps"), ring, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return now }

	if _, err := store.Persist(Record{ID: "expired", Plain: []byte("old"), ReceivedAt: now.Add(-2 * time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Persist(Record{ID: "fresh", Plain: []byte("new"), ReceivedAt: now.Add(-time.Minute)}); err != nil {
		t.Fatal(err)
	}

	entries, _ := os.ReadDir(store.Dir())
	if len(entries) != 2 {
		t.Fatalf("expected 2 artifacts, got %d", len(entries))
	}

	removed, err := store.Sweep()
	if err != nil {
		t.Fatal(err)
	}
	if removed != 1 {
		t.Fatalf("expected 1 expired capture removed, got %d", removed)
	}
	entries, _ = os.ReadDir(store.Dir())
	if len(entries) != 1 || !strings.Contains(entries[0].Name(), "fresh") {
		t.Fatalf("only the fresh capture must remain, got %v", entries)
	}
}
