package security

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
)

// tokenizationVersion is mixed into the token pepper; bumping it invalidates
// previously issued tokens.
const tokenizationVersion = "httplab/tokenize/v1"

// Tokenizer replaces sensitive values with irreversible, deterministic
// tokens. The same value always maps to the same token *within a deployment*
// (so support/debug exports stay correlatable), but a token cannot be turned
// back into the value: it is keyed by an HMAC pepper derived from the KEK.
type Tokenizer struct {
	pepper []byte
}

// NewTokenizer derives the tokenization pepper from the keyring KEK.
func NewTokenizer(kek []byte) *Tokenizer {
	mac := hmac.New(sha256.New, kek)
	mac.Write([]byte(tokenizationVersion))
	return &Tokenizer{pepper: mac.Sum(nil)}
}

// Token renders the token for one sensitive value.
func (t *Tokenizer) Token(level Level, value []byte) string {
	mac := hmac.New(sha256.New, t.pepper)
	mac.Write(value)
	sum := mac.Sum(nil)
	return "tok" + strconv.Itoa(int(level)) + "_" + hex.EncodeToString(sum[:5])
}

// Apply replaces every span with its irreversible token. Spans are merged
// first, exactly like masking.
func (t *Tokenizer) Apply(data []byte, spans []Span) []byte {
	merged := MergeSpans(spans, len(data))
	if len(merged) == 0 {
		out := make([]byte, len(data))
		copy(out, data)
		return out
	}

	var b strings.Builder
	b.Grow(len(data))
	prev := 0
	for _, s := range merged {
		b.Write(data[prev:s.Start])
		b.WriteString(t.Token(s.Level, data[s.Start:s.End]))
		prev = s.End
	}
	b.Write(data[prev:])
	return []byte(b.String())
}
