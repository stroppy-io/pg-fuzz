package finalreport

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// Inputs locates everything the gather reads.
type Inputs struct {
	Repo, WSRoot, OSSFuzz string
	Prefix                string // the campaign's workspace prefix
	Now                   time.Time
}

// Gather assembles the whole data file.
//
// GATHER THEN RENDER, in that order, through a file. The renderer reads the
// JSON this writes, so the file is the contract between them -- and an
// archived data.json can be re-rendered years later without the tree that
// produced it.
func Gather(in Inputs, inventory json.RawMessage) (Data, error) {
	scripts := func(n string) string { return filepath.Join(in.Repo, "scripts", n) }

	// Every workspace of this campaign that has a corpus, excluding the
	// coverage build -- it measures rather than fuzzes.
	var workspaces []string
	ents, err := os.ReadDir(in.WSRoot)
	if err != nil {
		return Data{}, err
	}
	for _, e := range ents {
		n := e.Name()
		if !e.IsDir() || !hasPrefix(n, in.Prefix+"-") || hasSuffix(n, "-cov") {
			continue
		}
		if st, err := os.Stat(filepath.Join(in.WSRoot, n, "corpus")); err == nil && st.IsDir() {
			workspaces = append(workspaces, n)
		}
	}

	known := map[string]bool{}
	for _, ws := range workspaces {
		ents, _ := os.ReadDir(filepath.Join(in.WSRoot, ws, "corpus"))
		for _, e := range ents {
			if hasSuffix(e.Name(), "_fuzzer") {
				known[e.Name()] = true
			}
		}
	}

	d := Data{
		Workspaces: GatherWorkspaces(in.WSRoot, workspaces,
			scripts("ratchet-baseline.json"), scripts("ratchet-series.jsonl")),
		Coverage:   ReadCoverage(scripts("coverage-series.jsonl")),
		Components: ReadComponents(scripts("coverage-components.jsonl")),
		Patches: GatherPatches(in.Repo, []string{
			filepath.Join(in.WSRoot, in.Prefix+"-und", "workspace.conf"),
			filepath.Join(in.WSRoot, in.Prefix+"-add", "workspace.conf"),
		}, HarnessFiles),
		Runtime: GatherRuntime(scripts("ratchet-series.jsonl"), in.WSRoot, in.Prefix),
		Masked: GatherMasked(MaskedInputs{
			KnownStarved: scripts("known-starved.tsv"),
			Baseline:     scripts("ratchet-baseline.json"),
			Series:       scripts("ratchet-series.jsonl"),
			Today:        in.Now,
		}),
		Inventory: inventory,
		Findings:  GatherFindings(filepath.Join(in.WSRoot, "FINDINGS"), known),
		Generated: in.Now.Format("2006-01-02 15:04:05 MST"),
	}
	return d, nil
}

func hasPrefix(s, p string) bool { return len(s) >= len(p) && s[:len(p)] == p }
func hasSuffix(s, p string) bool { return len(s) >= len(p) && s[len(s)-len(p):] == p }
