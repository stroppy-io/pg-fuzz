package scenario

import "strings"

// The driver itself lives in internal/incontainer: it runs inside the builder
// image, as this same binary, against a postmaster it started. Nothing about a
// scenario is rendered into a script for a shell to interpret.
//
// What stays here is the wire between the two halves. The in-container driver
// prints one machine-readable line, and the host reads it back.

// ResultLine extracts the driver's verdict from a run's output.
func ResultLine(out string) string {
	for _, l := range strings.Split(out, "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(l), "SFZ-RESULT: "); ok {
			return v
		}
	}
	return ""
}
