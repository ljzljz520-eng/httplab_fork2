package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// EnvelopeVersion / magic type carried by every encrypted artifact.
const (
	EnvelopeVersion = 1
	EnvelopeType    = "httplab-envelope/v1"
	EnvelopeScheme  = "AES-256-GCM"
)

// Envelope is the on-disk JSON representation of an encrypted payload.
//
// A fresh random data-encryption-key (DEK) is generated per artifact and
// used to encrypt the payload. The DEK itself is wrapped (encrypted) with
// the long-lived key-encryption-key (KEK) held by the Keyring: this is
// classic envelope encryption, so rotating/protecting the KEK is enough to
// protect every artifact and the bulk key never leaves the process.
type Envelope struct {
	Type       string     `json:"type"`
	Version    int        `json:"v"`
	Scheme     string     `json:"scheme"`
	WrapNonce  string     `json:"wrap_nonce"`
	WrappedDEK string     `json:"wrapped_dek"`
	Nonce      string     `json:"nonce"`
	Ciphertext string     `json:"ciphertext"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
}

// Keyring holds the KEK used to wrap per-payload DEKs.
type Keyring struct {
	kek    []byte
	source string
	path   string
}

// LoadOrCreateKeyring resolves the KEK in this order:
//
//  1. explicitKey (typically the HTTPLAB_MASTER_KEY environment variable,
//     raw or base64 encoded 32 bytes)
//  2. a key file at keyPath, created with mode 0600 on first use and
//     containing a base64 encoded random 32 byte key
func LoadOrCreateKeyring(explicitKey, keyPath string) (*Keyring, error) {
	if explicitKey != "" {
		kek, err := decodeKey(explicitKey)
		if err != nil {
			return nil, fmt.Errorf("master key: %v", err)
		}
		return &Keyring{kek: kek, source: "env"}, nil
	}

	if data, err := os.ReadFile(keyPath); err == nil {
		kek, err := decodeKey(string(data))
		if err != nil {
			return nil, fmt.Errorf("key file %q: %v", keyPath, err)
		}
		return &Keyring{kek: kek, source: "file", path: keyPath}, nil
	} else if !os.IsNotExist(err) {
		return nil, err
	}

	kek := make([]byte, 32)
	if _, err := rand.Read(kek); err != nil {
		return nil, err
	}
	encoded := base64.StdEncoding.EncodeToString(kek)
	if err := os.WriteFile(keyPath, []byte(encoded+"\n"), 0600); err != nil {
		return nil, err
	}
	return &Keyring{kek: kek, source: "file", path: keyPath}, nil
}

// Source reports where the KEK came from ("env" / "file").
func (k *Keyring) Source() string { return k.source }

// NewTokenizer builds the irreversible export tokenizer keyed by this KEK.
func (k *Keyring) NewTokenizer() *Tokenizer { return NewTokenizer(k.kek) }

func decodeKey(s string) ([]byte, error) {
	s = trimSpace(s)
	if raw, err := base64.StdEncoding.DecodeString(s); err == nil && len(raw) == 32 {
		return raw, nil
	}
	if raw := []byte(s); len(raw) == 32 {
		return raw, nil
	}
	return nil, fmt.Errorf("key must be 32 raw bytes or base64 encoded 32 bytes")
}

func trimSpace(s string) string {
	for len(s) > 0 && (s[0] == '\n' || s[0] == '\r' || s[0] == ' ' || s[0] == '\t') {
		s = s[1:]
	}
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r' || s[len(s)-1] == ' ' || s[len(s)-1] == '\t') {
		s = s[:len(s)-1]
	}
	return s
}

func newAESGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func randomNonce(g cipher.AEAD) ([]byte, error) {
	nonce := make([]byte, g.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return nonce, nil
}

// Seal encrypts plaintext with a fresh DEK and wraps the DEK with the KEK.
// ttl > 0 stamps an expiry on the envelope, used by the capture store
// sweeper.
func (k *Keyring) Seal(plaintext []byte, ttl time.Duration, now time.Time) ([]byte, error) {
	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		return nil, err
	}

	payloadAEAD, err := newAESGCM(dek)
	if err != nil {
		return nil, err
	}
	nonce, err := randomNonce(payloadAEAD)
	if err != nil {
		return nil, err
	}
	ciphertext := payloadAEAD.Seal(nil, nonce, plaintext, nil)

	kekAEAD, err := newAESGCM(k.kek)
	if err != nil {
		return nil, err
	}
	wrapNonce, err := randomNonce(kekAEAD)
	if err != nil {
		return nil, err
	}
	wrappedDEK := kekAEAD.Seal(nil, wrapNonce, dek, nil)

	env := Envelope{
		Type:       EnvelopeType,
		Version:    EnvelopeVersion,
		Scheme:     EnvelopeScheme,
		WrapNonce:  base64.StdEncoding.EncodeToString(wrapNonce),
		WrappedDEK: base64.StdEncoding.EncodeToString(wrappedDEK),
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
		CreatedAt:  now.UTC(),
	}
	if ttl > 0 {
		exp := env.CreatedAt.Add(ttl)
		env.ExpiresAt = &exp
	}
	return json.MarshalIndent(env, "", "  ")
}

// Open decrypts an envelope produced by Seal.
func (k *Keyring) Open(blob []byte) ([]byte, error) {
	var env Envelope
	if err := json.Unmarshal(blob, &env); err != nil {
		return nil, fmt.Errorf("envelope: %v", err)
	}
	if env.Type != EnvelopeType || env.Version != EnvelopeVersion || env.Scheme != EnvelopeScheme {
		return nil, fmt.Errorf("envelope: unsupported artifact %q v%d (%s)", env.Type, env.Version, env.Scheme)
	}

	wrapNonce, err := base64.StdEncoding.DecodeString(env.WrapNonce)
	if err != nil {
		return nil, err
	}
	wrappedDEK, err := base64.StdEncoding.DecodeString(env.WrappedDEK)
	if err != nil {
		return nil, err
	}
	nonce, err := base64.StdEncoding.DecodeString(env.Nonce)
	if err != nil {
		return nil, err
	}
	ciphertext, err := base64.StdEncoding.DecodeString(env.Ciphertext)
	if err != nil {
		return nil, err
	}

	kekAEAD, err := newAESGCM(k.kek)
	if err != nil {
		return nil, err
	}
	dek, err := kekAEAD.Open(nil, wrapNonce, wrappedDEK, nil)
	if err != nil {
		return nil, fmt.Errorf("envelope: DEK unwrap failed: %v", err)
	}

	payloadAEAD, err := newAESGCM(dek)
	if err != nil {
		return nil, err
	}
	plaintext, err := payloadAEAD.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("envelope: payload decrypt failed: %v", err)
	}
	return plaintext, nil
}

// EnvelopeExpired reports whether an envelope artifact is expired. Malformed
// artifacts are reported as expired so the sweeper removes them.
func EnvelopeExpired(blob []byte, now time.Time) bool {
	var env Envelope
	if err := json.Unmarshal(blob, &env); err != nil {
		return true
	}
	return env.ExpiresAt != nil && now.UTC().After(*env.ExpiresAt)
}

// Fingerprint returns a short, non reversible SHA-256 based fingerprint of a
// sensitive value, suitable for audit logs (preimage resistant, so the
// original secret can not be recovered from the log).
func Fingerprint(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:8])
}
