package fuzz

import (
	"bufio"
	"os"
	"strconv"
	"strings"
)

// PER-TARGET BUDGETS, which the port dropped entirely.
//
// Every target got one number, and that is wrong in both directions: a target
// that replays a large corpus needs longer before it fuzzes at all, and a fast
// one given the slow one's budget wastes the difference. The tuner that
// maintains the table survived -- `corpus -autocap -tune-budget` writes it --
// so the port kept the writer and dropped the reader, which is this codebase's
// signature failure in the other direction for once.
//
// The table is per (workspace, target), because the same target replays
// different corpora in different workspaces.

// SlowDefaults are the two targets known to need longer, used when the table
// says nothing. Measured, not guessed: both replay large corpora before they
// reach the mutation loop.
var SlowDefaults = map[string]int{
	"spi_query_fuzzer":    150,
	"simple_query_fuzzer": 200,
}

// Budgets is a tuned table, keyed by workspace then target.
type Budgets map[string]map[string]int

// LoadBudgets reads scripts/target-budgets.tsv: workspace, target, seconds.
//
// A missing file is not an error. The table is an optimisation over a default
// that is always available, and refusing to run without it would make a tuning
// aid into a dependency.
func LoadBudgets(path string) Budgets {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	b := Budgets{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) < 3 {
			continue
		}
		secs, err := strconv.Atoi(strings.TrimSpace(f[2]))
		if err != nil || secs <= 0 {
			continue
		}
		ws := strings.TrimSpace(f[0])
		if b[ws] == nil {
			b[ws] = map[string]int{}
		}
		b[ws][strings.TrimSpace(f[1])] = secs
	}
	return b
}

// For returns the budget for one target: the tuned value, else a known-slow
// default, else the caller's.
func (b Budgets) For(ws, target string, def int) int {
	if per, ok := b[ws]; ok {
		if v, ok := per[target]; ok {
			return v
		}
	}
	if v, ok := SlowDefaults[target]; ok {
		return v
	}
	return def
}
