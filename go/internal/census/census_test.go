package census

import (
	"strings"
	"testing"
)

// The leak rule is separate because the ASan rule cannot match a leak at all,
// and the consequence was not a mangled signature but NO signature: a campaign
// whose most interesting result was fifteen distinct leak sites consolidated
// to zero leak rows.
func TestLeaksAreExtractedOnceEach(t *testing.T) {
	log := `
==12==ERROR: LeakSanitizer: detected memory leaks
Direct leak of 32768 byte(s) in 4 object(s) allocated from:
    #0 0x55 in malloc
DEDUP_TOKEN: ___interceptor_malloc--AllocSetContextCreateInternal--spi_dest_startup
SUMMARY: AddressSanitizer: 32768 byte(s) leaked in 4 allocation(s).
`
	got := Extract(log)
	var leaks int
	for _, h := range got {
		if strings.HasPrefix(h.Sig, "LEAK in ") {
			leaks++
			if h.Sig != "LEAK in spi_dest_startup" {
				t.Errorf("signature = %q, want the allocation site", h.Sig)
			}
		}
	}
	// Exactly once: libFuzzer prints a DEDUP_TOKEN beside every leak, so a
	// SUMMARY rule would match the same report a second time -- it produced
	// four phantom hits against four real ones when that was tried.
	if leaks != 1 {
		t.Errorf("%d leak signatures from one report, want 1", leaks)
	}
}

func TestUBSanOperandsCollapse(t *testing.T) {
	// Operands differ on every hit. Keeping them turns one site into a
	// thousand signatures and the census stops grouping anything.
	a := Extract("/src/x/timestamp.c:2016:17: runtime error: signed integer overflow: 218415015 * 86400000000 cannot be represented in type 'long'")
	b := Extract("/src/x/timestamp.c:2016:17: runtime error: signed integer overflow: 999 * 42 cannot be represented in type 'long'")
	if len(a) != 1 || len(b) != 1 {
		t.Fatalf("got %d and %d signatures", len(a), len(b))
	}
	if a[0].Sig != b[0].Sig {
		t.Errorf("two hits at one site produced different signatures:\n %s\n %s", a[0].Sig, b[0].Sig)
	}
	if !strings.Contains(a[0].Sig, "timestamp.c:2016") {
		t.Errorf("the site was lost: %q", a[0].Sig)
	}
}

// The differential the whole three-way matrix exists for.
func TestVanillaSightingBeatsOrioleOnly(t *testing.T) {
	b := New()
	b.Add("oriole17-add", "spi_query_fuzzer", "TRAP: failed Assert(\"x\"), File: \"/src/a.c\", Line: 1")
	rows := b.Rows()
	if !rows[0].OrioleOnly {
		t.Error("seen only on oriole must be marked oriole_only")
	}
	b.Add("pg17-head-add", "spi_query_fuzzer", "TRAP: failed Assert(\"x\"), File: \"/src/a.c\", Line: 1")
	rows = b.Rows()
	if rows[0].OrioleOnly {
		t.Error("seen on a vanilla workspace too -- it is PostgreSQL's, not OrioleDB's")
	}
	if len(rows[0].VanillaWS) != 1 {
		t.Errorf("vanilla_ws = %v", rows[0].VanillaWS)
	}
}

// The prefilter must not change what the census finds. Every marker is a
// literal the corresponding pattern cannot match without, so a line the filter
// rejects could not have matched anything -- and this pins that rather than
// asserting it.
func TestPrefilterKeepsEverySignature(t *testing.T) {
	lines := []string{
		`---- spi_query_fuzzer ----`,
		`TRAP: failed Assert("ix_descr->nPrimaryFields == 1"), File: "bitmap_scan.c", Line: 230`,
		`/src/postgres/src/backend/utils/adt/numutils.c:123:4: runtime error: signed integer overflow`,
		`SUMMARY: AddressSanitizer: heap-buffer-overflow /src/x.c in foo`,
		`==1==ERROR: libFuzzer: out-of-memory (malloc(1234))`,
		`DEDUP_TOKEN: a--MemoryContextAlloc`,
		`PANIC:  could not write to file`,
		`FATAL:  the database system is starting up`,
		// The bulk of a real log, none of which can match anything.
		`#1048576	pulse  cov: 1189 ft: 6858 corp: 1604/497Kb exec/s: 6120 rss: 60Mb`,
		`INFO: seed corpus: files: 1604 min: 1b max: 4096b`,
	}
	for _, l := range lines {
		want := len(Extract(l)) > 0 || reBanner.MatchString(l)
		if got := interesting([]byte(l)); want && !got {
			t.Errorf("the filter dropped a line that matches:\n  %s", l)
		}
	}
	// And it does reject the volume: the two progress lines above.
	rejected := 0
	for _, l := range lines[len(lines)-2:] {
		if !interesting([]byte(l)) {
			rejected++
		}
	}
	if rejected != 2 {
		t.Errorf("the filter kept %d of 2 progress lines; it is not filtering", 2-rejected)
	}
}
