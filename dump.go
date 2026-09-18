package httplab

import (
	"fmt"
	"net/http"
	"regexp"
)

var decolorizeRegex = regexp.MustCompile("\x1b\\[0;\\d+m")

// Decolorize strips ANSI color codes produced by Render.
func Decolorize(s []byte) []byte {
	return decolorizeRegex.ReplaceAll(s, nil)
}

func valueOrDefault(value, def string) string {
	if value == "" {
		return def
	}
	return value
}

func withColor(color int, text string) string {
	return fmt.Sprintf("\x1b[0;%dm%s\x1b[0;0m", color, text)
}

// DumpRequest renders a request exactly like CaptureRequest.Render(false):
// full color, no masking. It is kept as the unclassified entry point used by
// tooling and tests; the UI goes through CaptureRequest with a policy.
func DumpRequest(req *http.Request) ([]byte, error) {
	c, err := CaptureRequest(req, nil)
	if err != nil {
		return nil, err
	}
	return c.Render(false), nil
}
