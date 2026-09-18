package security

import (
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Record is the storage-neutral projection of a captured request used by the
// encrypted capture store.
type Record struct {
	ID         string
	Method     string
	URI        string
	RemoteAddr string
	ReceivedAt time.Time
	Plain      []byte
	Spans      []Span
}

// Store persists captured requests to a managed directory using envelope
// encryption. Every artifact carries an expiry timestamp; Sweep
// irrecoverably deletes expired files.
type Store struct {
	dir  string
	ring *Keyring
	ttl  time.Duration
	now  func() time.Time
}

// NewStore opens (creating with 0700) the capture directory.
func NewStore(dir string, ring *Keyring, ttl time.Duration) (*Store, error) {
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	if err := tightenPerms(dir, 0700); err != nil {
		return nil, err
	}
	return &Store{dir: dir, ring: ring, ttl: ttl, now: time.Now}, nil
}

// Dir returns the managed directory.
func (s *Store) Dir() string { return s.dir }

// TTL reports the configured capture retention window.
func (s *Store) TTL() time.Duration { return s.ttl }

// Persist encrypts and writes one record, returning the file path.
func (s *Store) Persist(rec Record) (string, error) {
	if rec.ReceivedAt.IsZero() {
		rec.ReceivedAt = s.now()
	}
	blob, err := s.ring.Seal(rec.Plain, s.ttl, rec.ReceivedAt)
	if err != nil {
		return "", err
	}
	name := sanitizeName(rec.ID)
	if name == "" {
		name = "request"
	}
	path := filepath.Join(s.dir, rec.ReceivedAt.UTC().Format("20060102T150405.000000000")+"-"+name+".enc")

	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, blob, 0600); err != nil {
		return "", err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return "", err
	}
	return path, nil
}

// Sweep deletes expired envelope artifacts, returning the removed count.
func (s *Store) Sweep() (int, error) {
	now := s.now()
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return 0, err
	}
	removed := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".enc") {
			continue
		}
		path := filepath.Join(s.dir, e.Name())
		blob, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		if EnvelopeExpired(blob, now) {
			if err := os.Remove(path); err == nil {
				removed++
			}
		}
	}
	return removed, nil
}

func sanitizeName(name string) string {
	name = strings.TrimSpace(name)
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		case r == '/' || r == os.PathSeparator:
			b.WriteRune('-')
		default:
			b.WriteRune('-')
		}
	}
	return b.String()
}
