package security

// Minimal JSONPath implementation used by the classification engine.
//
// Supported syntax:
//
//	$                 root
//	$.foo             object member
//	$['foo']          object member (bracketed)
//	$[0]              array index
//	$[*]              any member/element
//	$..foo            recursive descent: member foo at any depth
//
// It intentionally covers the subset required by data-loss-prevention
// policies, not the full JSONPath specification.

// SegKind discriminates concrete and compiled path segments.
type SegKind int

const (
	SegKey SegKind = iota
	SegIndex
	SegAny
)

// PathSeg is one JSONPath segment. Deep marks a recursive-descent segment
// (only used by compiled policy patterns).
type PathSeg struct {
	Kind  SegKind
	Key   string
	Index int
	Deep  bool
}

func compileJSONPath(pattern string) ([]PathSeg, error) {
	if pattern == "" || pattern[0] != '$' {
		return nil, ErrInvalidJSONPath(pattern)
	}

	var segs []PathSeg
	i := 1
	for i < len(pattern) {
		deep := false
		if i+1 < len(pattern) && pattern[i] == '.' && pattern[i+1] == '.' {
			deep = true
			i += 2
		} else if pattern[i] == '.' {
			i++
		}

		switch {
		case i >= len(pattern):
			if deep {
				return nil, ErrInvalidJSONPath(pattern)
			}
		case pattern[i] == '[':
			seg, n, err := parseBracket(pattern[i:])
			if err != nil {
				return nil, err
			}
			seg.Deep = deep
			segs = append(segs, seg)
			i += n
		default:
			// bare identifier after . or ..
			start := i
			for i < len(pattern) && pattern[i] != '.' && pattern[i] != '[' {
				i++
			}
			if start == i {
				return nil, ErrInvalidJSONPath(pattern)
			}
			segs = append(segs, PathSeg{Kind: SegKey, Key: pattern[start:i], Deep: deep})
		}
	}
	return segs, nil
}

// parseBracket parses a bracket expression at the start of s and returns the
// segment plus the number of bytes consumed.
func parseBracket(s string) (PathSeg, int, error) {
	// s[0] == '['
	end := indexByte(s, ']')
	if end < 0 {
		return PathSeg{}, 0, ErrInvalidJSONPath(s)
	}
	inner := s[1:end]
	if inner == "*" {
		return PathSeg{Kind: SegAny}, end + 1, nil
	}
	if len(inner) > 0 && (inner[0] == '\'' || inner[0] == '"') {
		quote := inner[0]
		if len(inner) < 2 || inner[len(inner)-1] != quote {
			return PathSeg{}, 0, ErrInvalidJSONPath(s)
		}
		return PathSeg{Kind: SegKey, Key: inner[1 : len(inner)-1]}, end + 1, nil
	}
	idx := 0
	if inner == "" {
		return PathSeg{}, 0, ErrInvalidJSONPath(s)
	}
	for _, c := range inner {
		if c < '0' || c > '9' {
			return PathSeg{}, 0, ErrInvalidJSONPath(s)
		}
		idx = idx*10 + int(c-'0')
	}
	return PathSeg{Kind: SegIndex, Index: idx}, end + 1, nil
}

func indexByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}

type pathError string

func (e pathError) Error() string { return "invalid jsonpath: " + string(e) }

// ErrInvalidJSONPath marks a malformed policy pattern.
func ErrInvalidJSONPath(p string) error { return pathError(p) }

func segEqual(pat, concrete PathSeg) bool {
	switch pat.Kind {
	case SegAny:
		return true
	case SegKey:
		return concrete.Kind == SegKey && pat.Key == concrete.Key
	case SegIndex:
		return concrete.Kind == SegIndex && pat.Index == concrete.Index
	}
	return false
}

// MatchJSONPath reports whether a concrete path matches the compiled
// pattern.
func matchJSONPath(pattern, path []PathSeg) bool {
	if len(pattern) == 0 {
		return len(path) == 0
	}

	head := pattern[0]
	if !head.Deep {
		if len(path) == 0 || !segEqual(head, path[0]) {
			return false
		}
		return matchJSONPath(pattern[1:], path[1:])
	}

	// Recursive segment: it may consume zero or more concrete segments.
	for j := 0; j < len(path); j++ {
		if segEqual(head, path[j]) && matchJSONPath(pattern[1:], path[j+1:]) {
			return true
		}
	}
	return false
}
