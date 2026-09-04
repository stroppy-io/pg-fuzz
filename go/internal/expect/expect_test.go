package expect

import (
	"os"
	"path/filepath"
	"testing"
)

const list = `# function	scope	file	class	reference	added
do_to_timestamp	ci-rel_16*-undefined,pg16*und*	formatting.c	signed-overflow	FINDINGS/README.md	2026-09-04
date2j	ci-rel_16*-undefined	datetime.c	signed-overflow	FINDINGS/README.md	2026-09-04
tm2timestamp	ci-rel_17*-undefined	timestamp.c	signed-overflow	FINDINGS/README.md	2026-09-04
`

func load(t *testing.T) []Want {
	t.Helper()
	p := filepath.Join(t.TempDir(), "ci-findings.tsv")
	if err := os.WriteFile(p, []byte(list), 0o644); err != nil {
		t.Fatal(err)
	}
	w, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(w) != 3 {
		t.Fatalf("expected 3 rows, got %d", len(w))
	}
	return w
}

// FOUND AND REPORTED ARE DIFFERENT CLAIMS, and the gap between them is the
// whole reason there are two columns. A harness that still parses UBSan output
// but has quietly stopped carrying it into the census produces found=true and
// reported=false -- every log is correct, every report is empty, and a check
// that only read the logs would call that healthy.
func TestFoundIsNotReported(t *testing.T) {
	wants := load(t)
	seen := map[string]bool{"do_to_timestamp": true, "date2j": true}
	reported := map[string]bool{"formatting.c": true} // datetime.c never arrived

	res := Check(wants, "ci-rel_16_stable-undefined", seen, reported)
	if len(res) != 2 {
		t.Fatalf("two rows are scoped to this workspace, got %d", len(res))
	}
	byFn := map[string]Result{}
	for _, r := range res {
		byFn[r.Want.Function] = r
	}
	if !byFn["do_to_timestamp"].OK() {
		t.Fatal("found and reported should hold")
	}
	if r := byFn["date2j"]; !r.Found || r.Reported || r.OK() {
		t.Fatalf("date2j fired but never reached the census; got %+v", r)
	}
	if n := Missing(res); n != 1 {
		t.Fatalf("expected 1 missing, got %d", n)
	}
}

// THE SANITIZER IS PART OF THE SCOPE. A UBSan site cannot fire in an ASan
// build, so asserting one there fails a healthy workspace for a reason that
// has nothing to do with the harness. The first draft of the list did this.
func TestScopeExcludesTheWrongSanitizer(t *testing.T) {
	wants := load(t)
	if res := Check(wants, "ci-rel_16_stable-address", nil, nil); len(res) != 0 {
		t.Fatalf("no row should be asserted against an address build, got %d", len(res))
	}
	// And a row scoped to another major is not evidence here either.
	res := Check(wants, "ci-rel_17_stable-undefined", nil, nil)
	if len(res) != 1 || res[0].Want.Function != "tm2timestamp" {
		t.Fatalf("only the 17 row applies to a 17 workspace, got %+v", res)
	}
	// The legacy naming still matches, so one list serves both schemes.
	if res := Check(wants, "pg16-11-und", nil, nil); len(res) != 1 {
		t.Fatalf("pg16*und* should match pg16-11-und, got %d", len(res))
	}
}
