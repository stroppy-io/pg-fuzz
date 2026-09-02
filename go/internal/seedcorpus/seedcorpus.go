// Package seedcorpus generates seed corpora for the fuzz targets from a
// PostgreSQL source tree.
//
// WHY NOT JUST ZIP UP src/test/regress/sql, the way upstream OSS-Fuzz does?
// Two reasons:
//
//   - Those files are hundreds of kilobytes each. libFuzzer's default -max_len
//     is 4096, so most of every seed is thrown away, and the ones that survive
//     are far too large to mutate usefully. They are split into individual
//     statements instead.
//
//   - Most of these targets consume the FIRST BYTE of the input as a variant
//     selector -- which type to parse as, which parse mode, which encoding. A
//     seed without a correct leading selector byte is decoded as a different
//     variant than the text was written for, so the right byte is prepended:
//     the value pulled out of jsonb.sql gets the jsonb selector, and so on.
//
// Seeds are named by CONTENT HASH, so re-running is idempotent and never
// clobbers inputs the fuzzer itself has discovered.
package seedcorpus

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// MaxSeed is the largest seed worth writing. Beyond this libFuzzer discards
// most of it anyway.
const MaxSeed = 8192

// WriteSeed writes one seed, named for its content. Reports whether it is new.
func WriteSeed(outdir string, payload []byte) bool {
	if len(payload) == 0 || len(payload) > MaxSeed {
		return false
	}
	sum := sha1.Sum(payload)
	name := hex.EncodeToString(sum[:])[:16]
	path := filepath.Join(outdir, name)
	if _, err := os.Stat(path); err == nil {
		return false
	}
	if os.WriteFile(path, payload, 0o644) != nil {
		return false
	}
	return true
}

// read returns a file's BYTES, unchanged.
//
// The implementation this replaces decoded as UTF-8 with errors="replace",
// which rewrites every invalid byte as U+FFFD. That matters here and nowhere
// else: these files are a catalog of pathological values, and
// collate.linux.utf8.sql deliberately contains bytes that are not valid UTF-8.
// Replacing them produces a seed that says "efbfbd" where the source said
// "e4" -- destroying the exact input the target is most interesting on.
//
// The two differ on 24 of about 40,000 seeds. Seeds are content-hashed and
// additive, so this adds the faithful ones and stops producing the mangled
// ones; nothing already in a corpus is invalidated.
func read(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(b)
}

// SQLStatements splits every regress .sql file into individual statements.
func SQLStatements(sqldir string) []string {
	ents, err := os.ReadDir(sqldir)
	if err != nil {
		return nil
	}
	var names []string
	for _, e := range ents {
		if strings.HasSuffix(e.Name(), ".sql") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)

	var out []string
	for _, n := range names {
		for _, stmt := range strings.Split(read(filepath.Join(sqldir, n)), ";") {
			var keep []string
			for _, line := range strings.Split(stmt, "\n") {
				// Comment lines carry no statement, and a seed that is only
				// comments is a seed the target returns from immediately.
				if !strings.HasPrefix(strings.TrimLeft(line, " \t"), "--") {
					keep = append(keep, line)
				}
			}
			s := strings.TrimSpace(strings.Join(keep, "\n"))
			if s != "" {
				out = append(out, s+";")
			}
		}
	}
	return out
}

var literalRe = regexp.MustCompile(`'((?:[^']|'')*)'`)

// Literals pulls single-quoted values out of specific regress files.
//
// Those files are precisely a catalog of every interesting and every
// pathological value the PostgreSQL developers could think of for that type,
// which makes them a far better starting corpus than anything generated.
func Literals(sqldir string, filenames []string) []string {
	var out []string
	for _, n := range filenames {
		text := read(filepath.Join(sqldir, n))
		for _, m := range literalRe.FindAllStringSubmatch(text, -1) {
			v := strings.ReplaceAll(m[1], "''", "'")
			if v != "" {
				out = append(out, v)
			}
		}
	}
	return out
}

// Result is one target's contribution.
type Result struct {
	Target string
	Added  int
	Have   int
}

// Generate writes the plan into corpusdir.
func Generate(srcdir, corpusdir, extraGlobs string, out io.Writer) (int, error) {
	sqldir := filepath.Join(srcdir, "src", "test", "regress", "sql")
	if st, err := os.Stat(sqldir); err != nil || !st.IsDir() {
		return 0, fmt.Errorf("no regress SQL at %s", sqldir)
	}
	// The extension is exported here for the orioledb flavor. WITHOUT THESE
	// SEEDS the OrioleDB workspaces fuzz stock PostgreSQL with an unused
	// extension loaded: the regress SQL never writes "USING orioledb", so the
	// storage engine is never reached.
	isOrioleDB := false
	if st, err := os.Stat(filepath.Join(srcdir, "orioledb")); err == nil && st.IsDir() {
		isOrioleDB = true
	}

	plan := BuildPlan(sqldir)

	// Extra seeds go to the targets that take WHOLE STATEMENTS. The
	// type-level targets take bare literals, so feeding them here is noise.
	stmtTargets := []string{"spi_query_fuzzer", "simple_query_fuzzer", "raw_parser_fuzzer"}
	if extraGlobs != "" {
		extra := ExtraStatements(srcdir, extraGlobs)
		if len(extra) > 0 {
			fmt.Fprintf(out, "extra seeds from %s: %d statements\n", extraGlobs, len(extra))
			for _, t := range stmtTargets {
				plan[t] = append(plan[t], withPrefix(t, extra)...)
			}
		}
	}
	if isOrioleDB {
		for _, t := range stmtTargets {
			plan[t] = append(plan[t], withPrefix(t, OrioleDBStatements)...)
		}
	}

	var targets []string
	for t := range plan {
		targets = append(targets, t)
	}
	sort.Strings(targets)

	total := 0
	for _, t := range targets {
		outdir := filepath.Join(corpusdir, t)
		if err := os.MkdirAll(outdir, 0o755); err != nil {
			return total, err
		}
		added := 0
		for _, s := range plan[t] {
			if WriteSeed(outdir, s) {
				added++
			}
		}
		ents, _ := os.ReadDir(outdir)
		total += added
		fmt.Fprintf(out, "%-24s +%-6d (%d total)\n", t, added, len(ents))
	}
	fmt.Fprintf(out, "\n%d new seed(s)\n", total)
	return total, nil
}

// withPrefix applies the target's selector byte, if it takes one.
func withPrefix(target string, stmts []string) [][]byte {
	var out [][]byte
	for _, s := range stmts {
		if target == "raw_parser_fuzzer" {
			// Selector 0 == RAW_PARSE_DEFAULT.
			out = append(out, append([]byte{0}, []byte(s)...))
		} else {
			out = append(out, []byte(s))
		}
	}
	return out
}

// ExtraStatements reads statements from workspace-configured extra paths.
//
// A patch under evaluation usually ships its own regression tests, and without
// them the corpus never mentions anything the patch adds -- so the features it
// introduces are never exercised no matter how long the fuzzer runs.
// Configured per workspace so this file stays ignorant of any particular fork.
func ExtraStatements(srcdir, globs string) []string {
	var out []string
	for _, pattern := range strings.Fields(globs) {
		paths, _ := filepath.Glob(filepath.Join(srcdir, pattern))
		sort.Strings(paths)
		for _, p := range paths {
			if !strings.HasSuffix(p, ".sql") {
				continue
			}
			for _, stmt := range strings.Split(read(p), ";") {
				if s := strings.TrimSpace(stmt); s != "" {
					out = append(out, s+";")
				}
			}
		}
	}
	return out
}
