package scenario

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The port must render exactly what the Python generator rendered.
//
// The recorded .sql files carry a comment header the generator writes and this
// does not; everything from the first CREATE onward is compared line by line.
// A single differing line fails the fixture and names it, because that is the
// class of divergence -- a missing TABLESPACE, a partition boundary off by one
// -- that would otherwise surface as "the finding stopped reproducing".
func TestRenderMatchesRecordedSQL(t *testing.T) {
	files, _ := filepath.Glob(filepath.Join("testdata", "*.json"))
	if len(files) == 0 {
		t.Fatal("no fixtures")
	}
	var pass, skipped int
	for _, f := range files {
		name := filepath.Base(f)
		t.Run(name, func(t *testing.T) {
			jb, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			sb, err := os.ReadFile(strings.TrimSuffix(f, ".json") + ".sql")
			if err != nil {
				t.Skip("no recorded sql")
			}
			rec, err := UnmarshalStrict(jb)
			if err != nil {
				t.Fatal(err)
			}
			// SOME RECORDED .sql ARE TRANSCRIPTS, NOT RENDERINGS.
			//
			// When a scenario killed the server the generator captured psql's
			// output into the same file, so it carries "server closed the
			// connection unexpectedly" and friends. Those cannot be goldens
			// for a renderer. Skipped explicitly and counted, never silently:
			// a suite that quietly drops a third of its fixtures and reports
			// green is the failure this project keeps finding in its own
			// instruments.
			if !isPureSQL(string(sb)) {
				skipped++
				t.Skip("recorded sql is a session transcript, not a rendering")
			}
			// THE RECORDED DATABASE NAME IS NOT PART OF THE RENDERING.
			//
			// The Python generator connected to `postgres` and so rendered
			// `ALTER DATABASE postgres`; the Go driver creates and connects to
			// `dbfuzz`. Rendering `postgres` here would be fidelity to a
			// transcript and a bug in the tool -- the statement succeeds and
			// silently configures a database nothing then uses, which is how
			// default_tablespace, the precondition behind the motivating
			// finding, was recorded, rendered, executed, and not in effect.
			//
			// So the fixture's database name is normalised to the one the
			// driver actually uses, and everything else still has to match
			// byte for byte.
			want := body(strings.ReplaceAll(string(sb),
				"ALTER DATABASE postgres ", "ALTER DATABASE "+SetupDB+" "))
			got := body(RenderSetup(rec.Scenario))
			if len(want) == 0 {
				t.Skip("recorded sql has no statements")
			}
			for i := 0; i < len(want) || i < len(got); i++ {
				var w, g string
				if i < len(want) {
					w = want[i]
				}
				if i < len(got) {
					g = got[i]
				}
				if w != g {
					t.Fatalf("line %d\n want: %s\n  got: %s", i+1, w, g)
				}
			}
			pass++
		})
	}
	t.Logf("%d rendered identically, %d skipped as transcripts, %d fixtures",
		pass, skipped, len(files))
}

// isPureSQL rejects a file that carries captured client output.
func isPureSQL(s string) bool {
	for _, bad := range []string{
		"This probably means", "server closed the connection",
		"connection to server was lost", "psql:",
		"\nDETAIL:", "\nERROR:", "\nHINT:", "\nCONTEXT:", "\nWARNING:",
	} {
		if strings.Contains(s, bad) {
			return false
		}
	}
	return true
}

// body drops the generator's comment header and blank lines.
func body(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		l = strings.TrimRight(l, " \t")
		if l == "" || strings.HasPrefix(l, "--") {
			continue
		}
		out = append(out, l)
	}
	return out
}
