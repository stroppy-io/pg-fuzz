package repro

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Two runs of one defect differ in the pid and the build path, so the raw
// crash line cannot be a dedup key -- grouping on it splits one finding into
// as many rows as it was reproduced. The census normalises log-derived
// signatures; the reproduce path kept the whole line and had no consumer to
// notice.
func TestNormaliseSignatureCollapsesTwoRunsOfOneDefect(t *testing.T) {
	a := "SUMMARY: AddressSanitizer: heap-buffer-overflow " +
		"/src/postgres/bld/../src/backend/access/transam/xlogreader.c:1952:3 in DecodeXLogRecord"
	b := "SUMMARY: AddressSanitizer: heap-buffer-overflow " +
		"/src/postgres/bld/../src/backend/access/transam/xlogreader.c:1952:3 in DecodeXLogRecord"
	withPID := "==21==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x7d13"
	otherPID := "==4242==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x7d13"

	if NormaliseSignature(a) != NormaliseSignature(b) {
		t.Error("identical crashes normalised differently")
	}
	if NormaliseSignature(withPID) != NormaliseSignature(otherPID) {
		t.Errorf("the pid survived normalisation:\n %s\n %s",
			NormaliseSignature(withPID), NormaliseSignature(otherPID))
	}
	if strings.Contains(NormaliseSignature(a), "/src/postgres/bld/../") {
		t.Error("the build path survived normalisation")
	}
	// Two DIFFERENT defects must stay apart.
	c := strings.Replace(a, "1952", "1983", 1)
	if NormaliseSignature(a) == NormaliseSignature(c) {
		t.Error("two different lines collapsed into one signature")
	}
}

// A coverage build does not fail: it SUCCEEDS and reports nothing, which is
// indistinguishable from "no crash". Sweeping artifacts against one yields a
// clean sheet that means nothing at all.
func TestSweepRefusesASanitizerThatCannotReport(t *testing.T) {
	_, err := Sweep(context.Background(), t.TempDir(), t.TempDir(), "img", "coverage", 1, nil)
	if err == nil {
		t.Fatal("a coverage build was swept")
	}
	if !strings.Contains(err.Error(), "cannot report") {
		t.Errorf("the refusal does not explain itself: %v", err)
	}
}

// Every reproduction fails identically against an empty build directory, and
// the report read "131 artifacts, all did not reproduce".
func TestSweepRefusesAnEmptyBuildDirectory(t *testing.T) {
	_, err := Sweep(context.Background(), t.TempDir(), t.TempDir(), "img", "address", 1, nil)
	if err == nil {
		t.Fatal("a sweep ran against a build directory with no targets")
	}
	if !strings.Contains(err.Error(), "did not reproduce") {
		t.Errorf("the refusal does not name the failure it prevents: %v", err)
	}
}

func TestIsArtifactCoversEveryKindLibFuzzerWrites(t *testing.T) {
	for _, n := range []string{"crash-abc", "leak-abc", "timeout-abc", "oom-abc"} {
		if !IsArtifact(n) {
			t.Errorf("%s is not recognised as a reproducer", n)
		}
	}
	for _, n := range []string{"run-1.log", "fuzz-0.log", "seed", "corpus"} {
		if IsArtifact(n) {
			t.Errorf("%s was treated as a reproducer", n)
		}
	}
}

func TestGroupBySignatureCountsDistinctDefects(t *testing.T) {
	rs := []SweepResult{
		{Target: "a", Signature: "X"}, {Target: "a", Signature: "X"},
		{Target: "b", Signature: "Y"},
	}
	g := GroupBySignature(rs)
	if len(g) != 2 || len(g["X"]) != 2 || len(g["Y"]) != 1 {
		t.Errorf("grouping = %v", g)
	}
}

func TestBuiltTargetsNeedsTheExecuteBit(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "a_fuzzer"), []byte("ELF"), 0o755)
	os.WriteFile(filepath.Join(dir, "b_fuzzer"), []byte("not built"), 0o644)
	got, err := builtTargets(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != "a_fuzzer" {
		t.Errorf("builtTargets = %v, want [a_fuzzer]", got)
	}
}
