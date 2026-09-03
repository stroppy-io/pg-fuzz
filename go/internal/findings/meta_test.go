package findings

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func mkFinding(t *testing.T, root, name, body string) {
	t.Helper()
	d := filepath.Join(root, name)
	if err := os.MkdirAll(d, 0o755); err != nil {
		t.Fatal(err)
	}
	if body != "" {
		if err := os.WriteFile(filepath.Join(d, "README.md"), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// THE FIELD MUST NOT QUIETLY STOP BEING THERE.
//
// Attribution used to be recoverable only by reading prose and guessing. The
// **Found by:** field ended that, and every finding on disk now carries one --
// but nothing stopped the next write-up being added without it, at which point
// every report goes back to inferring.
func TestMissingMetaFindsWriteupsWithoutAttribution(t *testing.T) {
	root := t.TempDir()
	mkFinding(t, root, "has-it", "# t\n\n**Found by:** `spi_query_fuzzer`\n")
	mkFinding(t, root, "lacks-it", "# t\n\nA defect, described in prose only.\n")
	mkFinding(t, root, "no-writeup", "")

	got := MissingMeta(root)
	want := []string{"lacks-it", "no-writeup"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("MissingMeta = %v, want %v", got, want)
	}
}

// WHAT IS NOT A FINDING must not be reported as one. FINDINGS is its own git
// repo, and `.git` was once counted as a PostgreSQL-core finding; the dated
// directories are campaign records and `reports` holds rendered documents.
func TestMissingMetaSkipsWhatIsNotAFinding(t *testing.T) {
	root := t.TempDir()
	mkFinding(t, root, ".git", "")
	mkFinding(t, root, "reports", "")
	mkFinding(t, root, "2026-08-02-storage-matrix", "# a campaign record\n")

	if got := MissingMeta(root); len(got) != 0 {
		t.Errorf("MissingMeta = %v, want none of these counted", got)
	}
}

// The real corpus passes, which is the point of adding the gate now rather
// than as a wish.
func TestTheRealCorpusHasAttributionEverywhere(t *testing.T) {
	root := "/home/dead/pgfuzz/FINDINGS"
	if _, err := os.Stat(root); err != nil {
		t.Skip("no findings corpus on this machine")
	}
	if got := MissingMeta(root); len(got) != 0 {
		t.Errorf("write-ups with no **Found by:** line: %v", got)
	}
}
