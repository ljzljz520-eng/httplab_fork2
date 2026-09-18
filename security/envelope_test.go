package security

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newTestKeyring(t *testing.T) *Keyring {
	t.Helper()
	dir := t.TempDir()
	k, err := LoadOrCreateKeyring("", filepath.Join(dir, "master.key"))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestKeyringCreatesKeyFileWith0600(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "master.key")
	k, err := LoadOrCreateKeyring("", path)
	if err != nil {
		t.Fatal(err)
	}
	if k.Source() != "file" {
		t.Errorf("expected file source, got %q", k.Source())
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("key file perm = %o, want 0600", perm)
	}

	// Reload must reuse the same key.
	k2, err := LoadOrCreateKeyring("", path)
	if err != nil {
		t.Fatal(err)
	}
	blob, err := k.Seal([]byte("roundtrip"), 0, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	plain, err := k2.Open(blob)
	if err != nil || string(plain) != "roundtrip" {
		t.Fatalf("reloaded keyring must open sealed data, got %q / %v", plain, err)
	}
}

func TestKeyringAcceptsExplicitBase64Key(t *testing.T) {
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = byte(i)
	}
	encoded := base64.StdEncoding.EncodeToString(raw)
	k, err := LoadOrCreateKeyring(encoded, "")
	if err != nil {
		t.Fatal(err)
	}
	if k.Source() != "env" {
		t.Errorf("expected env source, got %q", k.Source())
	}
}

func TestEnvelopeRoundTrip(t *testing.T) {
	k := newTestKeyring(t)
	secret := []byte("GET / HTTP/1.1\nAuthorization: Bearer abcdefgh12345678\n")
	now := time.Now()

	blob, err := k.Seal(secret, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}

	if strings.Contains(string(blob), "abcdefgh12345678") {
		t.Error("ciphertext envelope must not contain the plaintext secret")
	}
	if !strings.Contains(string(blob), EnvelopeType) {
		t.Error("envelope must carry its type marker")
	}

	plain, err := k.Open(blob)
	if err != nil {
		t.Fatal(err)
	}
	if string(plain) != string(secret) {
		t.Errorf("round trip mismatch:\n got %q\nwant %q", plain, secret)
	}

	if !EnvelopeExpired(blob, now.Add(2*time.Hour)) {
		t.Error("envelope should be expired after its TTL")
	}
	if EnvelopeExpired(blob, now.Add(time.Minute)) {
		t.Error("envelope should still be valid within its TTL")
	}
}

func TestEnvelopeNoTTLNeverExpires(t *testing.T) {
	k := newTestKeyring(t)
	blob, err := k.Seal([]byte("data"), 0, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if EnvelopeExpired(blob, time.Now().Add(10*365*24*time.Hour)) {
		t.Error("envelope without TTL must never expire")
	}
}

func TestEnvelopeWrongKeyFails(t *testing.T) {
	k1 := newTestKeyring(t)
	k2 := newTestKeyring(t)

	blob, err := k1.Seal([]byte("topsecret"), 0, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := k2.Open(blob); err == nil {
		t.Error("opening with a different KEK must fail")
	}
}

func TestEnvelopeTamperDetection(t *testing.T) {
	k := newTestKeyring(t)
	blob, err := k.Seal([]byte("topsecret"), 0, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	// Flip a byte in the middle of the file (JSON area).
	idx := len(blob) / 2
	blob[idx] ^= 0xFF
	if _, err := k.Open(blob); err == nil {
		t.Error("tampered envelope must fail authentication")
	}
}

func TestFingerprintNonReversible(t *testing.T) {
	fp := Fingerprint([]byte("hunter2"))
	if len(fp) != 16 {
		t.Errorf("fingerprint length = %d, want 16 hex chars", len(fp))
	}
	if Fingerprint([]byte("hunter2")) != fp {
		t.Error("fingerprint must be deterministic")
	}
	if Fingerprint([]byte("hunter3")) == fp {
		t.Error("different values must have different fingerprints")
	}
}
