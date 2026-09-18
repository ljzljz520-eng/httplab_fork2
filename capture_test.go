package httplab

import (
	"bytes"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gchaincl/httplab/security"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func spanAt(spans []security.Span, plain []byte, location string) (security.Span, string, bool) {
	for _, s := range spans {
		if s.Location == location {
			return s, string(plain[s.Start:s.End]), true
		}
	}
	return security.Span{}, "", false
}

func TestCaptureClassifiesJSONHeadersAndQuery(t *testing.T) {
	body := `{"user":{"password":"hunter2","name":"bob"},"items":[{"token":"abc"}]}`
	req, err := http.NewRequest("POST", "/login?token=q1w2e3r4", bytes.NewBufferString(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer abcdefgh12345678")
	req.Header.Set("Cookie", "session=abc; foo=bar")
	req.RemoteAddr = "10.0.0.1:1234"

	policy := security.NewDefaultPolicy()
	cap, err := CaptureRequest(req, policy)
	require.NoError(t, err)
	cap.ID = "req-1"

	plain := string(cap.Plain)

	// JSONPath spans carry exact, valid offsets into the indented body.
	if s, val, ok := spanAt(cap.Spans, cap.Plain, "$.user.password"); assert.True(t, ok, "password jsonpath span missing") {
		assert.Equal(t, `"hunter2"`, val)
		assert.Equal(t, security.LevelSecret, s.Level)
		assert.Equal(t, security.KindJSONPath, s.Kind)
	}
	if _, val, ok := spanAt(cap.Spans, cap.Plain, "$.items[0].token"); assert.True(t, ok, "nested token jsonpath span missing") {
		assert.Equal(t, `"abc"`, val)
	}

	// Header span covers the whole Authorization value.
	if _, val, ok := spanAt(cap.Spans, cap.Plain, "header:Authorization"); assert.True(t, ok) {
		assert.Equal(t, "Bearer abcdefgh12345678", val)
	}
	if _, val, ok := spanAt(cap.Spans, cap.Plain, "header:Cookie"); assert.True(t, ok) {
		assert.Equal(t, "session=abc; foo=bar", val)
	}

	// Query string is classified with form-field rules.
	var queryLeak string
	for _, s := range cap.Spans {
		if strings.HasPrefix(s.Location, "query:") {
			queryLeak += plain[s.Start:s.End]
		}
	}
	assert.Contains(t, queryLeak, "q1w2e3r4")

	// Default render is masked: no secret reaches the screen bytes.
	masked := string(Decolorize(cap.Render(true)))
	assert.NotContains(t, masked, "hunter2")
	assert.NotContains(t, masked, "q1w2e3r4")
	assert.NotContains(t, masked, "abcdefgh12345678")
	assert.NotContains(t, masked, "session=abc")
	assert.Contains(t, masked, security.MaskMarker(security.LevelSecret))
	if count := cap.MaskedCount(); count < 4 {
		t.Errorf("expected at least 4 masked spans, got %d", count)
	}

	// Non sensitive context survives masking.
	assert.Contains(t, masked, "POST /login?")
	assert.Contains(t, masked, `"name": "bob"`)

	// Explicit reveal shows the plain values again.
	revealed := string(Decolorize(cap.Render(false)))
	assert.Contains(t, revealed, "hunter2")
	assert.Contains(t, revealed, "abcdefgh12345678")
}

func TestCaptureClassifiesFormBody(t *testing.T) {
	body := "name=bob&password=hunter2&token=XYZ987"
	req, err := http.NewRequest("POST", "/form", bytes.NewBufferString(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	cap, err := CaptureRequest(req, security.NewDefaultPolicy())
	require.NoError(t, err)

	if _, val, ok := spanAt(cap.Spans, cap.Plain, "form:password"); assert.True(t, ok) {
		assert.Equal(t, "hunter2", val)
	}
	if _, val, ok := spanAt(cap.Spans, cap.Plain, "form:token"); assert.True(t, ok) {
		assert.Equal(t, "XYZ987", val)
	}
	assert.NotContains(t, string(Decolorize(cap.Render(true))), "hunter2")
}

func TestCaptureClassifiesMultipartForm(t *testing.T) {
	body := "--B\r\n" +
		"Content-Disposition: form-data; name=\"password\"\r\n" +
		"\r\n" +
		"s3cr3t\r\n" +
		"--B--\r\n"
	req, err := http.NewRequest("POST", "/upload", bytes.NewBufferString(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "multipart/form-data; boundary=B")

	cap, err := CaptureRequest(req, security.NewDefaultPolicy())
	require.NoError(t, err)

	if _, val, ok := spanAt(cap.Spans, cap.Plain, "form:password"); assert.True(t, ok) {
		assert.Equal(t, "s3cr3t", val)
	}
	assert.NotContains(t, string(Decolorize(cap.Render(true))), "s3cr3t")
}

func TestCaptureClassifiesRawBodyRegex(t *testing.T) {
	body := "aws_access_key_id=AKIAIOSFODNN7EXAMPLE"
	req, err := http.NewRequest("PUT", "/raw", bytes.NewBufferString(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "text/plain")

	cap, err := CaptureRequest(req, security.NewDefaultPolicy())
	require.NoError(t, err)

	var matched bool
	for _, s := range cap.Spans {
		if s.RuleID == "builtin/regex-aws-access-key" &&
			string(cap.Plain[s.Start:s.End]) == "AKIAIOSFODNN7EXAMPLE" {
			matched = true
		}
	}
	assert.True(t, matched, "AWS access key regex span missing or misaligned")
	assert.NotContains(t, string(Decolorize(cap.Render(true))), "AKIAIOSFODNN7EXAMPLE")
}

func TestCaptureWithoutPolicyIsFullRender(t *testing.T) {
	req, err := http.NewRequest("GET", "/x?password=hunter2", bytes.NewBufferString(`{"password":"hunter2"}`))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer abcdefgh12345678")

	cap, err := CaptureRequest(req, nil)
	require.NoError(t, err)
	assert.Empty(t, cap.Spans)
	assert.Equal(t, 0, cap.MaskedCount())
	assert.Contains(t, string(Decolorize(cap.Render(true))), "hunter2")
}

func TestCaptureRecordAndEgress(t *testing.T) {
	body := `{"password":"hunter2"}`
	req, err := http.NewRequest("POST", "/egress", bytes.NewBufferString(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "127.0.0.1:9999"

	cap, err := CaptureRequest(req, security.NewDefaultPolicy())
	require.NoError(t, err)
	cap.ID = "req-9"

	// Record projection carries plain + spans for the encrypted store.
	rec := cap.Record()
	assert.Equal(t, "req-9", rec.ID)
	assert.Equal(t, "POST", rec.Method)
	assert.Equal(t, "/egress", rec.URI)
	assert.Equal(t, "127.0.0.1:9999", rec.RemoteAddr)
	assert.NotEmpty(t, rec.Plain)
	assert.NotEmpty(t, rec.Spans)

	// Tokenized export: irreversible, no secret survives.
	keyPath := filepath.Join(t.TempDir(), "master.key")
	ring, err := security.LoadOrCreateKeyring("", keyPath)
	require.NoError(t, err)
	tokenized := ring.NewTokenizer().Apply(cap.PlainCopy(), cap.Spans)
	require.NotNil(t, tokenized)
	assert.NotContains(t, string(tokenized), "hunter2")
	assert.Contains(t, string(tokenized), "tok3_")

	// Encrypted at rest and recoverable.
	blob, err := ring.Seal(cap.PlainCopy(), 0, cap.ReceivedAt)
	require.NoError(t, err)
	assert.NotContains(t, string(blob), "hunter2")
	plain, err := ring.Open(blob)
	require.NoError(t, err)
	assert.Equal(t, cap.PlainCopy(), plain)
}

func TestCaptureRespectsLowLevelRule(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.json")
	require.NoError(t, os.WriteFile(policyPath, []byte(`{
		"rules": [
			{"id": "trace-header", "kind": "header", "pattern": "X-Trace", "level": 1}
		]
	}`), 0600))
	policy, err := security.LoadPolicyFile(policyPath)
	require.NoError(t, err)

	req, err := http.NewRequest("GET", "/", bytes.NewBufferString(""))
	require.NoError(t, err)
	req.Header.Set("X-Trace", "keep-visible-1234")
	req.Header.Set("Authorization", "Bearer abcdefgh12345678")

	cap, err := CaptureRequest(req, policy)
	require.NoError(t, err)

	// L1 spans are classified (metadata) but not masked nor tokenized.
	var foundLow bool
	for _, s := range cap.Spans {
		if s.RuleID == "trace-header" {
			foundLow = true
		}
	}
	assert.True(t, foundLow)
	masked := string(Decolorize(cap.Render(true)))
	assert.Contains(t, masked, "keep-visible-1234")
	assert.NotContains(t, masked, "abcdefgh12345678")
	if cap.MaskedCount() == 0 {
		t.Error("authorization must still count as masked while L1 header is ignored")
	}

	keyPath := filepath.Join(t.TempDir(), "master.key")
	ring, err := security.LoadOrCreateKeyring("", keyPath)
	require.NoError(t, err)
	tokenized := string(ring.NewTokenizer().Apply(cap.PlainCopy(), cap.SensitiveSpans()))
	assert.Contains(t, tokenized, "keep-visible-1234")
	assert.NotContains(t, tokenized, "abcdefgh12345678")
}

func TestCapturePlainCopyIsImmutable(t *testing.T) {
	req, _ := http.NewRequest("GET", "/", bytes.NewBufferString("x"))
	cap, err := CaptureRequest(req, nil)
	require.NoError(t, err)
	cp := cap.PlainCopy()
	cp[0] = 'Z'
	assert.NotEqual(t, byte('Z'), cap.Plain[0])
}
