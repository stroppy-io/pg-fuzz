package build

import (
	"bytes"
	"io"
	"strings"
)

// Filter thins a build's LIVE output. The log file is never filtered.
//
// WHY. oss-fuzz runs build.sh under shell tracing, and PostgreSQL's make
// echoes every compiler invocation, so one build emits megabytes -- 3.1 MB for
// a single workspace here. GitHub truncates a step log at a fixed size, which
// meant a failing sweep item could not be diagnosed from its own log at all:
// the trace ran off the end long before the failure, and every diagnosis had
// to come from the uploaded artifact instead. Locally it is the same problem
// wearing a friendlier face -- the interesting line scrolls past.
//
// SAFE BY CONSTRUCTION, because this only ever touches the copy going to the
// screen. Fuzzers() tees into a buffer that is written to build.log whole,
// pass or fail, and the failure path already prints interesting() plus the
// path to that file. Nothing that is dropped here is lost.
//
// What goes is the mechanical noise and nothing else: shell xtrace, and the
// compiler command lines. What stays is build.sh's own messages, configure's
// checks, warnings, errors and the summaries -- which is what a person is
// watching for.
func Filter(w io.Writer) io.Writer {
	if w == nil {
		return nil
	}
	return &filter{w: w}
}

type filter struct {
	w   io.Writer
	buf bytes.Buffer
}

func (f *filter) Write(p []byte) (int, error) {
	// Line-oriented, so a partial write cannot be judged on half a line.
	f.buf.Write(p)
	for {
		i := bytes.IndexByte(f.buf.Bytes(), '\n')
		if i < 0 {
			break
		}
		line := string(f.buf.Next(i + 1))
		if !drop(strings.TrimRight(line, "\n")) {
			if _, err := io.WriteString(f.w, line); err != nil {
				return len(p), err
			}
		}
	}
	return len(p), nil
}

// drop reports whether a line is mechanical noise.
//
// An ERROR IS NEVER DROPPED, whatever it looks like. A compiler line that
// carries a diagnostic is the one compiler line worth seeing, and dropping it
// because it starts with "clang" would defeat the purpose of the whole
// exercise.
func drop(s string) bool {
	t := strings.TrimSpace(s)
	if strings.Contains(t, "error:") || strings.Contains(t, "warning:") ||
		strings.Contains(t, "FAILED") || strings.Contains(t, "undefined reference") {
		return false
	}
	// Shell xtrace, from build.sh running under -x.
	if strings.HasPrefix(t, "+ ") || t == "+" {
		return true
	}
	// A compiler or archiver invocation echoed by make.
	for _, p := range []string{"gcc ", "g++ ", "clang ", "clang++ ", "ar ", "ranlib "} {
		if strings.HasPrefix(t, p) {
			return true
		}
	}
	return strings.Contains(t, " -c -o ")
}
