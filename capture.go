package httplab

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"mime"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gchaincl/httplab/security"
)

// Capture is a single request captured at the collection boundary.
//
// Plain holds the canonical, color-free textual render (request line,
// headers, body) and Spans marks the sensitive byte ranges *inside Plain*.
// All masking / tokenization / encryption consumers operate on that pair,
// so offsets remain stable across the whole pipeline.
type Capture struct {
	ID         string
	Method     string
	URI        string
	RemoteAddr string
	ReceivedAt time.Time

	Plain []byte
	Spans []security.Span

	// MaskLevel is the policy threshold captured at ingestion time: only
	// spans at or above it are masked/tokenized. Zero means "never mask"
	// (unclassified captures).
	MaskLevel security.Level
}

// SensitiveSpans returns the spans subject to masking/export controls.
func (c *Capture) SensitiveSpans() []security.Span {
	if c.MaskLevel == 0 {
		return nil
	}
	out := make([]security.Span, 0, len(c.Spans))
	for _, s := range c.Spans {
		if s.Level >= c.MaskLevel {
			out = append(out, s)
		}
	}
	return out
}

// CaptureRequest reads req and classifies it. When policy is nil no span is
// produced but the render is identical.
func CaptureRequest(req *http.Request, policy *security.Policy) (*Capture, error) {
	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}

	reqURI := req.RequestURI
	if reqURI == "" {
		reqURI = req.URL.RequestURI()
	}

	buf := bytes.NewBuffer(nil)

	// Request line ------------------------------------------------------
	lineStart := buf.Len()
	fmt.Fprintf(buf, "%s %s HTTP/%d.%d\n",
		valueOrDefault(req.Method, "GET"),
		reqURI,
		req.ProtoMajor,
		req.ProtoMinor,
	)
	requestLine := buf.Bytes()[lineStart:]

	var spans []security.Span
	if policy != nil {
		spans = append(spans, scanRegex(policy, security.ScopeHeaders, requestLine, lineStart, "request-line")...)
		// The URI starts at len(METHOD)+1 inside the request line.
		uriStart := len(valueOrDefault(req.Method, "GET")) + 1
		if qi := strings.IndexByte(reqURI, '?'); qi >= 0 {
			spans = append(spans, scanFormPairs(policy, reqURI[qi+1:], lineStart+uriStart+qi+1, "query")...)
		}
	}

	// Headers -----------------------------------------------------------
	keys := sortedHeaderKeys(req)
	for _, key := range keys {
		val := req.Header.Get(key)
		lineStart = buf.Len()
		fmt.Fprintf(buf, "%s: %s\n", key, val)

		if policy == nil {
			continue
		}
		if val != "" {
			if rule := policy.MatchHeader(key); rule != nil {
				valueStart := lineStart + len(key) + 2
				spans = append(spans, security.Span{
					Start:    valueStart,
					End:      valueStart + len(val),
					Level:    rule.Level,
					RuleID:   rule.ID,
					Kind:     security.KindHeader,
					Location: "header:" + key,
				})
			}
			line := buf.Bytes()[lineStart:]
			spans = append(spans, scanRegex(policy, security.ScopeHeaders, line, lineStart, "header:"+key)...)
		}
	}

	// Body --------------------------------------------------------------
	renderedBody := body
	if len(body) > 0 {
		buf.WriteRune('\n') // blank separator line, mirrors legacy dump
	}
	bodyBase := buf.Len()

	contentType := req.Header.Get("Content-Type")
	bodySpans, indented := classifyBody(body, contentType, policy)
	if indented != nil {
		renderedBody = indented
	}
	buf.Write(renderedBody)
	if policy != nil {
		for i := range bodySpans {
			bodySpans[i].Start += bodyBase
			bodySpans[i].End += bodyBase
		}
		spans = append(spans, bodySpans...)
	}

	var maskLevel security.Level
	if policy != nil {
		maskLevel = policy.MaskLevel
	}
	return &Capture{
		Method:     valueOrDefault(req.Method, "GET"),
		URI:        reqURI,
		RemoteAddr: req.RemoteAddr,
		ReceivedAt: time.Now().UTC(),
		Plain:      buf.Bytes(),
		Spans:      spans,
		MaskLevel:  maskLevel,
	}, nil
}

// Render produces the colored view bytes. When mask is true every sensitive
// span is replaced with its level placeholder.
func (c *Capture) Render(mask bool) []byte {
	plain := c.Plain
	if mask {
		plain = security.ApplyMask(plain, c.SensitiveSpans())
	}
	return colorize(plain)
}

// PlainCopy returns a defensive copy of the plain render.
func (c *Capture) PlainCopy() []byte {
	out := make([]byte, len(c.Plain))
	copy(out, c.Plain)
	return out
}

// MaskedCount reports how many distinct sensitive values are hidden.
func (c *Capture) MaskedCount() int {
	return len(security.MergeSpans(c.SensitiveSpans(), len(c.Plain)))
}

// Record projects the capture for the encrypted capture store.
func (c *Capture) Record() security.Record {
	return security.Record{
		ID:         c.ID,
		Method:     c.Method,
		URI:        c.URI,
		RemoteAddr: c.RemoteAddr,
		ReceivedAt: c.ReceivedAt,
		Plain:      c.PlainCopy(),
		Spans:      c.Spans,
	}
}

// scanRegex applies in-scope regex rules to a text fragment; offsets are
// made absolute using base.
func scanRegex(policy *security.Policy, scope string, text []byte, base int, location string) []security.Span {
	var spans []security.Span
	for _, rule := range policy.RegexRules(scope) {
		for _, match := range rule.FindAllIndex(text) {
			spans = append(spans, security.Span{
				Start:    base + match[0],
				End:      base + match[1],
				Level:    rule.Level,
				RuleID:   rule.ID,
				Kind:     security.KindRegex,
				Location: location,
			})
		}
	}
	return spans
}

// scanFormPairs walks "a=1&b=2" style text keeping raw offsets.
func scanFormPairs(policy *security.Policy, raw string, base int, locationPrefix string) []security.Span {
	var spans []security.Span
	off := 0
	for len(raw) > 0 {
		pair := raw
		if amp := strings.IndexByte(raw, '&'); amp >= 0 {
			pair = raw[:amp]
		}

		key := pair
		valueStart, valueEnd := off+len(pair), off+len(pair)
		if eq := strings.IndexByte(pair, '='); eq >= 0 {
			key = pair[:eq]
			valueStart = off + eq + 1
			valueEnd = off + len(pair)
		}

		if decoded, err := url.QueryUnescape(key); err == nil {
			key = decoded
		}
		if rule := policy.MatchFormField(key); rule != nil && valueStart < valueEnd {
			spans = append(spans, security.Span{
				Start:    base + valueStart,
				End:      base + valueEnd,
				Level:    rule.Level,
				RuleID:   rule.ID,
				Kind:     security.KindForm,
				Location: locationPrefix + ":" + key,
			})
		}

		consumed := len(pair) + 1
		if consumed > len(raw) {
			break
		}
		raw = raw[consumed:]
		off += consumed
	}
	return spans
}

// classifyBody returns spans relative to the returned body text and, when
// the body is JSON, the indented render.
func classifyBody(body []byte, contentType string, policy *security.Policy) (spans []security.Span, rendered []byte) {
	if policy == nil || len(body) == 0 {
		return nil, nil
	}

	switch {
	case strings.Contains(contentType, "application/json"):
		var indented bytes.Buffer
		if err := json.Indent(&indented, body, "", "  "); err == nil {
			rendered = indented.Bytes()
			spans = append(spans, scanJSON(policy, rendered)...)
			spans = append(spans, scanRegex(policy, security.ScopeBody, rendered, 0, "body")...)
			return spans, rendered
		}
		// Invalid JSON: treat as raw text.
	case strings.Contains(contentType, "application/x-www-form-urlencoded"):
		spans = append(spans, scanFormPairs(policy, string(body), 0, "form")...)
	case strings.Contains(contentType, "multipart/form-data"):
		spans = append(spans, scanMultipart(policy, body, contentType)...)
	}

	spans = append(spans, scanRegex(policy, security.ScopeBody, body, 0, "body")...)
	return spans, nil
}

// jsonFrame tracks decoder state for one open container.
type jsonFrame struct {
	isArray    bool
	haveKey    bool
	pendingKey string
	index      int
	owned      bool // container occupies one segment of its parent path
}

// scanJSON walks indented JSON and tags scalar values whose concrete path
// matches a jsonpath rule. Offsets refer to the indented bytes.
func scanJSON(policy *security.Policy, data []byte) []security.Span {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()

	var frames []*jsonFrame
	var path []security.PathSeg
	var spans []security.Span

	pushValueLocation := func() bool {
		if len(frames) == 0 {
			return false
		}
		parent := frames[len(frames)-1]
		if parent.isArray {
			path = append(path, security.PathSeg{Kind: security.SegIndex, Index: parent.index})
			parent.index++
		} else {
			if !parent.haveKey {
				return false
			}
			path = append(path, security.PathSeg{Kind: security.SegKey, Key: parent.pendingKey})
		}
		return true
	}

	endValue := func(owned bool) {
		if owned {
			path = path[:len(path)-1]
		}
		if len(frames) > 0 && !frames[len(frames)-1].isArray {
			frames[len(frames)-1].haveKey = false
		}
	}

	classifyScalar := func(lit []byte, endOff int) {
		owned := pushValueLocation()
		defer endValue(owned)

		start := endOff - len(lit)
		if start < 0 || endOff > len(data) || !bytes.Equal(data[start:endOff], lit) {
			return
		}
		if rule := policy.MatchJSONPath(path); rule != nil {
			spans = append(spans, security.Span{
				Start:    start,
				End:      endOff,
				Level:    rule.Level,
				RuleID:   rule.ID,
				Kind:     security.KindJSONPath,
				Location: canonicalJSONPath(path),
			})
		}
	}

	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return spans
		}
		endOff := int(dec.InputOffset())

		switch tv := tok.(type) {
		case json.Delim:
			switch tv {
			case '{', '[':
				owned := pushValueLocation()
				frames = append(frames, &jsonFrame{isArray: tv == '[', owned: owned})
			case '}', ']':
				if len(frames) == 0 {
					return spans
				}
				fr := frames[len(frames)-1]
				frames = frames[:len(frames)-1]
				if fr.owned {
					path = path[:len(path)-1]
				}
				if len(frames) > 0 && !frames[len(frames)-1].isArray {
					frames[len(frames)-1].haveKey = false
				}
			}
		case string:
			if len(frames) > 0 && !frames[len(frames)-1].isArray && !frames[len(frames)-1].haveKey {
				frames[len(frames)-1].pendingKey = tv
				frames[len(frames)-1].haveKey = true
				continue
			}
			lit, _ := json.Marshal(tv)
			classifyScalar(lit, endOff)
		case json.Number:
			classifyScalar([]byte(string(tv)), endOff)
		case bool:
			classifyScalar([]byte(strconv.FormatBool(tv)), endOff)
		case nil:
			classifyScalar([]byte("null"), endOff)
		}
	}
	return spans
}

func canonicalJSONPath(path []security.PathSeg) string {
	var b strings.Builder
	b.WriteRune('$')
	for _, seg := range path {
		switch seg.Kind {
		case security.SegKey:
			b.WriteRune('.')
			b.WriteString(seg.Key)
		case security.SegIndex:
			b.WriteString(fmt.Sprintf("[%d]", seg.Index))
		default:
			b.WriteString("[*]")
		}
	}
	return b.String()
}

// scanMultipart tags named form-field values inside a multipart body.
func scanMultipart(policy *security.Policy, body []byte, contentType string) []security.Span {
	_, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		return nil
	}
	boundary := params["boundary"]
	if boundary == "" {
		return nil
	}
	delim := "--" + boundary

	var spans []security.Span
	pos := 0
	for {
		idx := bytes.Index(body[pos:], []byte(delim))
		if idx < 0 {
			break
		}
		partStart := pos + idx + len(delim)
		// Closing delimiter ("--boundary--") ends the body.
		if bytes.HasPrefix(body[partStart:], []byte("--")) {
			break
		}

		headerEnd, sepLen := indexHeaderSeparator(body[partStart:])
		if headerEnd < 0 {
			break
		}
		headerBlock := body[partStart : partStart+headerEnd]
		valueStart := partStart + headerEnd + sepLen

		next := bytes.Index(body[valueStart:], []byte(delim))
		if next < 0 {
			break
		}
		valueEnd := valueStart + next
		if valueEnd >= 2 {
			valueEnd -= 2 // strip trailing CRLF before the boundary
		}

		if name := multipartFieldName(string(headerBlock)); name != "" {
			if rule := policy.MatchFormField(name); rule != nil && valueStart < valueEnd {
				spans = append(spans, security.Span{
					Start:    valueStart,
					End:      valueEnd,
					Level:    rule.Level,
					RuleID:   rule.ID,
					Kind:     security.KindForm,
					Location: "form:" + name,
				})
			}
		}
		pos = valueStart + next
	}
	return spans
}

// indexHeaderSeparator returns the offset and length of the blank line
// separating part headers from the value (\r\n\r\n or \n\n).
func indexHeaderSeparator(block []byte) (int, int) {
	if idx := bytes.Index(block, []byte("\r\n\r\n")); idx >= 0 {
		return idx, 4
	}
	if idx := bytes.Index(block, []byte("\n\n")); idx >= 0 {
		return idx, 2
	}
	return -1, 0
}

func multipartFieldName(headerBlock string) string {
	for _, line := range strings.Split(headerBlock, "\n") {
		line = strings.TrimRight(strings.TrimRight(line, "\r"), " ")
		colon := strings.IndexByte(line, ':')
		if colon < 0 {
			continue
		}
		name := strings.TrimSpace(line[:colon])
		if !strings.EqualFold(name, "Content-Disposition") {
			continue
		}
		_, params, err := mime.ParseMediaType(strings.TrimSpace(line[colon+1:]))
		if err != nil {
			return ""
		}
		return params["name"]
	}
	return ""
}

// colorize applies the legacy terminal colors to the plain render.
// Masking happens before colorizing and only touches values, so the
// structural coloring is performed line by line without needing offsets.
// Everything after the blank separator line (the body) stays uncolored,
// matching the historical dump format.
func colorize(plain []byte) []byte {
	var b bytes.Buffer
	lines := strings.SplitAfter(string(plain), "\n")
	inBody := false
	for i, line := range lines {
		if line == "" {
			continue
		}
		content := line
		hadNL := false
		if strings.HasSuffix(content, "\n") {
			content = content[:len(content)-1]
			hadNL = true
		}

		switch {
		case inBody:
			b.WriteString(content)
		case i == 0:
			colorizeRequestLine(&b, content)
		case content == "":
			inBody = true
		default:
			colorizeHeaderLine(&b, content)
		}

		if hadNL {
			b.WriteRune('\n')
		}
	}
	return b.Bytes()
}

func colorizeRequestLine(b *bytes.Buffer, line string) {
	sp1 := strings.IndexByte(line, ' ')
	if sp1 <= 0 {
		b.WriteString(line)
		return
	}
	httpIdx := strings.LastIndex(line, "HTTP/")
	if httpIdx <= sp1 {
		b.WriteString(line)
		return
	}
	b.WriteString(withColor(35, line[:sp1]))
	b.WriteString(line[sp1:httpIdx])
	b.WriteString(withColor(35, "HTTP"))
	b.WriteString(line[httpIdx+len("HTTP"):])
}

func colorizeHeaderLine(b *bytes.Buffer, line string) {
	colon := strings.IndexByte(line, ':')
	if colon < 0 {
		b.WriteString(line)
		return
	}
	b.WriteString(withColor(31, line[:colon]))
	rest := line[colon:]
	if strings.HasPrefix(rest, ": ") {
		b.WriteString(": ")
		b.WriteString(withColor(32, rest[2:]))
	} else {
		b.WriteString(withColor(32, rest))
	}
}

// sortedHeaderKeys keeps DumpRequest ordering deterministic.
func sortedHeaderKeys(req *http.Request) []string {
	var keys []string
	for k := range req.Header {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
