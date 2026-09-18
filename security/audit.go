package security

import (
	"bufio"
	"encoding/json"
	"os"
	"sync"
	"time"
)

// Audit actions.
const (
	AuditReveal         = "reveal"
	AuditExport         = "export"
	AuditSaveEncrypted  = "save_encrypted"
	AuditCapturePersist = "capture_persist"
	AuditSweep          = "retention_sweep"
)

// Event is one audit record. Sensitive values never appear in an event:
// spans are projected to Snapshot (fingerprints only).
type Event struct {
	Time       time.Time  `json:"time"`
	ExpiresAt  time.Time  `json:"expires_at"`
	Action     string     `json:"action"`
	RequestID  string     `json:"request_id,omitempty"`
	Method     string     `json:"method,omitempty"`
	URI        string     `json:"uri,omitempty"`
	RemoteAddr string     `json:"remote_addr,omitempty"`
	Spans      []Snapshot `json:"spans,omitempty"`
	Detail     string     `json:"detail,omitempty"`
}

// Auditor is the audit sink.
type Auditor interface {
	Log(ev Event) error
}

// FileAuditor appends JSON-line events to a mode-0600 file and enforces
// retention.
type FileAuditor struct {
	mu        sync.Mutex
	path      string
	retention time.Duration
	now       func() time.Time
}

// NewFileAuditor opens (creating with 0600) the audit log at path.
func NewFileAuditor(path string, retention time.Duration) (*FileAuditor, error) {
	if retention <= 0 {
		retention = 7 * 24 * time.Hour
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}
	if err := f.Close(); err != nil {
		return nil, err
	}
	if err := tightenPerms(path, 0600); err != nil {
		return nil, err
	}
	return &FileAuditor{path: path, retention: retention, now: time.Now}, nil
}

// Log appends one event, stamping time and expiry when unset.
func (a *FileAuditor) Log(ev Event) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	now := a.now()
	if ev.Time.IsZero() {
		ev.Time = now.UTC()
	}
	if ev.ExpiresAt.IsZero() {
		ev.ExpiresAt = now.Add(a.retention).UTC()
	}

	line, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	line = append(line, '\n')

	f, err := os.OpenFile(a.path, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(line)
	return err
}

// Retention reports the configured retention window.
func (a *FileAuditor) Retention() time.Duration { return a.retention }

// Sweep drops expired records, rewriting the log in place. It returns the
// number of removed records.
func (a *FileAuditor) Sweep() (int, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.sweepLocked(a.now())
}

func (a *FileAuditor) sweepLocked(now time.Time) (int, error) {
	f, err := os.Open(a.path)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}

	var keep [][]byte
	removed := 0
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var ev Event
		if err := json.Unmarshal(line, &ev); err != nil ||
			(!ev.ExpiresAt.IsZero() && now.UTC().After(ev.ExpiresAt)) {
			removed++
			continue
		}
		cp := make([]byte, len(line))
		copy(cp, line)
		keep = append(keep, cp)
	}
	if err := scanner.Err(); err != nil {
		f.Close()
		return 0, err
	}
	if err := f.Close(); err != nil {
		return 0, err
	}

	if removed == 0 {
		return 0, nil
	}

	tmp := a.path + ".tmp"
	out, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return 0, err
	}
	for _, line := range keep {
		if _, err := out.Write(append(line, '\n')); err != nil {
			out.Close()
			os.Remove(tmp)
			return 0, err
		}
	}
	if err := out.Close(); err != nil {
		os.Remove(tmp)
		return 0, err
	}
	return removed, os.Rename(tmp, a.path)
}

func tightenPerms(path string, mode os.FileMode) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if info.Mode().Perm() != mode {
		return os.Chmod(path, mode)
	}
	return nil
}
