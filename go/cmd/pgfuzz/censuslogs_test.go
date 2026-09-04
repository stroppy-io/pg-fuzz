package main

import (
	"os"
	"path/filepath"
	"testing"

	"pgfuzz/internal/census"
)

// A SEALED CAMPAIGN'S LOGS ARE NOT IN THE WORKSPACE.
//
// The bundle's census walked the campaign's live/entries for the right list of
// workspaces and then looked for their logs under $PGFUZZ_WS/<ws>, which a
// sealed campaign never writes. Every sealed bundle therefore recorded
// "census: no logs to scan" -- indistinguishable from a campaign that crashed
// nowhere. This pins the distinction the fix rests on: the same workspace name
// resolves to two different directories, and only one of them has the logs.
func TestCensusReadsTheCampaignNotTheWorkspace(t *testing.T) {
	root := t.TempDir()
	const ws, slug, target = "gt-pg17", "grande-teste", "json_parser_fuzzer"

	// The sealed layout, which is where a campaign actually writes.
	sealed := filepath.Join(root, "campaigns", slug, "ws", ws)
	dir := filepath.Join(sealed, "artifacts", target)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	// The shape census actually recognises: it keys on the SUMMARY line, not
	// on the ERROR banner.
	log := "#1 INITED exec/s: 0 rss: 30Mb\n" +
		"==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0xdead\n" +
		"SUMMARY: AddressSanitizer: heap-buffer-overflow " +
		"/src/postgres/src/common/jsonapi.c:1234 in json_lex\n"
	if err := os.WriteFile(filepath.Join(dir, "run-20260903-010203.log"), []byte(log), 0o644); err != nil {
		t.Fatal(err)
	}

	// The workspace path -- the one the old code used -- holds nothing.
	empty := filepath.Join(root, ws)
	if err := os.MkdirAll(empty, 0o755); err != nil {
		t.Fatal(err)
	}
	if n := addLogsFrom(census.New(), empty, ws); n != 0 {
		t.Fatalf("the unsealed path should hold no logs, read %d", n)
	}

	// The campaign path holds them, which is the whole of the fix.
	b := census.New()
	n := addLogsFrom(b, sealed, ws)
	if n != 1 {
		t.Fatalf("expected 1 log from the sealed campaign, read %d", n)
	}
	if len(b.Rows()) == 0 {
		t.Fatal("a log was read but produced no signature")
	}
}
