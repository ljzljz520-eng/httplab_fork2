package security

import (
	"sort"
	"strings"
)

// Markers rendered in place of masked values. They are pure ASCII so they
// survive any terminal.
var markers = map[Level]string{
	LevelConfidential: "[REDACTED]",
	LevelSecret:       "[REDACTED-SECRET]",
}

// MaskMarker returns the placeholder used for a level.
func MaskMarker(l Level) string {
	if m, ok := markers[l]; ok {
		return m
	}
	return markers[LevelConfidential]
}

// MergeSpans normalizes a span set: it sorts spans, unites overlapping /
// adjacent ranges and keeps the highest level (and the first rule metadata)
// for each union. Offsets are clipped to dataLen.
func MergeSpans(spans []Span, dataLen int) []Span {
	if len(spans) == 0 {
		return nil
	}

	valid := spans[:0:0]
	for _, s := range spans {
		if s.Start < 0 {
			s.Start = 0
		}
		if s.End > dataLen {
			s.End = dataLen
		}
		if s.Start < s.End {
			valid = append(valid, s)
		}
	}
	if len(valid) == 0 {
		return nil
	}

	sort.SliceStable(valid, func(i, j int) bool {
		if valid[i].Start != valid[j].Start {
			return valid[i].Start < valid[j].Start
		}
		return valid[i].End < valid[j].End
	})

	merged := []Span{valid[0]}
	for _, s := range valid[1:] {
		last := &merged[len(merged)-1]
		if s.Start <= last.End {
			if s.End > last.End {
				last.End = s.End
			}
			if s.Level > last.Level {
				last.Level = s.Level
			}
			continue
		}
		merged = append(merged, s)
	}
	return merged
}

// ApplyMask replaces every span in data with the level's placeholder.
// Spans are merged first.
func ApplyMask(data []byte, spans []Span) []byte {
	merged := MergeSpans(spans, len(data))
	if len(merged) == 0 {
		// Return a copy so callers can never mutate the captured plaintext
		// through a masked render.
		out := make([]byte, len(data))
		copy(out, data)
		return out
	}

	var b strings.Builder
	b.Grow(len(data))
	prev := 0
	for _, s := range merged {
		b.Write(data[prev:s.Start])
		b.WriteString(MaskMarker(s.Level))
		prev = s.End
	}
	b.Write(data[prev:])
	return []byte(b.String())
}
