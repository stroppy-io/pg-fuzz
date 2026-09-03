package scenario

import "strings"

// transient are failures that mean the DATABASE WORKED, not that it broke.
//
// Under concurrency a serialization failure or a deadlock is the engine doing
// its job. Reporting one as a finding manufactures defects, which is worse
// than missing them: it teaches the reader that the scenario engine cries
// wolf. The old driver classified these explicitly and recorded them as notes;
// the port had no notion of them, so it either ignored every concurrent error
// or would have failed on the expected ones.
var transient = []string{
	"could not serialize access",
	"deadlock detected",
	"canceling statement due to lock timeout",
	"canceling statement due to statement timeout",
	"terminating connection due to conflict",
	"tuple concurrently updated",
	"tuple concurrently deleted",
}

// Transient reports whether an error message is a normal outcome of running
// two sessions at once.
func Transient(msg string) bool {
	m := strings.ToLower(msg)
	for _, s := range transient {
		if strings.Contains(m, s) {
			return true
		}
	}
	return false
}

// unsupported are refusals: the engine declining a thing it never claimed to
// do. A refusal is not a defect, and a scenario that asked for one has simply
// asked for something this build cannot provide.
var unsupported = []string{
	"is not supported",
	"not supported on",
	"cannot be used on",
	"unrecognized parameter",
	"does not support",
}

// Unsupported reports whether an error is the engine refusing rather than
// failing.
func Unsupported(msg string) bool {
	m := strings.ToLower(msg)
	for _, s := range unsupported {
		if strings.Contains(m, s) {
			return true
		}
	}
	return false
}
