package security

import (
	"strings"
	"testing"
)

func TestTokenizeIrreversibleAndDeterministic(t *testing.T) {
	k := newTestKeyring(t)
	tz := NewTokenizer(k.kek)

	data := []byte("Authorization: Bearer abcdefgh12345678\npassword=hunter2\npassword=hunter2\n")
	spans := []Span{
		{Start: 15, End: 38, Level: LevelSecret, RuleID: "header"}, // "Bearer abcdefgh12345678"
		{Start: 48, End: 55, Level: LevelSecret, RuleID: "form"},   // "hunter2"
		{Start: 65, End: 72, Level: LevelSecret, RuleID: "form"},   // "hunter2" again
	}

	out := string(tz.Apply(data, spans))

	if strings.Contains(out, "abcdefgh12345678") || strings.Contains(out, "hunter2") {
		t.Errorf("tokenized output leaked secrets: %q", out)
	}
	// Context must survive.
	if !strings.HasPrefix(out, "Authorization: ") || !strings.Contains(out, "password=") {
		t.Errorf("non sensitive context must be preserved: %q", out)
	}

	tok := tz.Token(LevelSecret, []byte("hunter2"))
	if strings.Count(out, tok) != 2 {
		t.Errorf("identical secrets must map to one identical token (count=2), got %q:\n%s", tok, out)
	}
	if !strings.HasPrefix(tok, "tok3_") {
		t.Errorf("secret token prefix wrong: %q", tok)
	}
	if tz.Token(LevelConfidential, []byte("x")) == tz.Token(LevelSecret, []byte("x")) {
		t.Error("different levels must produce different token prefixes")
	}
}

func TestTokenizeIsolationBetweenKeyrings(t *testing.T) {
	tz1 := NewTokenizer(newTestKeyring(t).kek)
	tz2 := NewTokenizer(newTestKeyring(t).kek)
	if tz1.Token(LevelSecret, []byte("hunter2")) == tz2.Token(LevelSecret, []byte("hunter2")) {
		t.Error("tokens must be deployment scoped via the KEK-derived pepper")
	}
}

func TestTokenizeWithoutSpansReturnsCopy(t *testing.T) {
	tz := NewTokenizer(newTestKeyring(t).kek)
	data := []byte("nothing sensitive")
	out := tz.Apply(data, nil)
	if string(out) != string(data) {
		t.Error("no spans means identical output")
	}
	out[0] = 'X'
	if data[0] == 'X' {
		t.Error("returned bytes must not alias the input")
	}
}
