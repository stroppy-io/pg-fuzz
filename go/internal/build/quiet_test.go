package build

import (
	"bytes"
	"strings"
	"testing"
)

// AN ERROR IS NEVER DROPPED, whatever it looks like. A compiler line carrying a
// diagnostic is the one compiler line worth seeing, and dropping it because it
// begins with "clang" would defeat the whole point of filtering.
func TestFilterKeepsWhatMatters(t *testing.T) {
	in := strings.Join([]string{
		"+ ./configure --enable-cassert",             // xtrace
		"checking for readline/readline.h... yes",    // configure, keep
		"gcc -Wall -c -o foo.o foo.c",                // make noise
		"clang -O1 -fsanitize=address -c bar.c",      // make noise
		"src/pg_background.c:99:2: error: #error",    // KEEP, though it is a compile line
		"clang: warning: argument unused",            // KEEP, a warning
		"+ echo 'build.sh: plugins built'",           // xtrace
		"build.sh: plugins built: pgsql-http",        // build.sh's own voice, keep
		"ar rcs libpgport.a x.o",                     // noise
		"ERROR: these plugins FAILED: pg_background", // KEEP
		"",
	}, "\n")

	var out bytes.Buffer
	f := Filter(&out)
	if _, err := f.Write([]byte(in)); err != nil {
		t.Fatal(err)
	}
	got := out.String()

	for _, keep := range []string{
		"checking for readline",
		"error: #error",
		"warning: argument unused",
		"build.sh: plugins built: pgsql-http",
		"FAILED: pg_background",
	} {
		if !strings.Contains(got, keep) {
			t.Errorf("dropped a line that must be kept: %q", keep)
		}
	}
	for _, gone := range []string{
		"./configure --enable-cassert",
		"-c -o foo.o",
		"fsanitize=address -c bar.c",
		"ar rcs",
	} {
		if strings.Contains(got, gone) {
			t.Errorf("kept mechanical noise: %q", gone)
		}
	}
}

// A PARTIAL WRITE MUST NOT BE JUDGED ON HALF A LINE. The stream arrives in
// whatever chunks the pipe delivers, and a filter that decided per-Write would
// classify the front of a line and lose the rest of it.
func TestFilterAcrossChunkBoundaries(t *testing.T) {
	var out bytes.Buffer
	f := Filter(&out)
	for _, chunk := range []string{"+ noi", "se here\nsrc/x.c:1:1: err", "or: boom\nkept\n"} {
		if _, err := f.Write([]byte(chunk)); err != nil {
			t.Fatal(err)
		}
	}
	got := out.String()
	if strings.Contains(got, "noise here") {
		t.Errorf("xtrace split across writes leaked through: %q", got)
	}
	if !strings.Contains(got, "error: boom") || !strings.Contains(got, "kept") {
		t.Errorf("a line split across writes was lost: %q", got)
	}
}

// A nil sink stays nil, so Fuzzers still recognises "no live output".
func TestFilterNil(t *testing.T) {
	if Filter(nil) != nil {
		t.Fatal("Filter(nil) must stay nil")
	}
}
