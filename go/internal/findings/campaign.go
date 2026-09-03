package findings

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
)

// THE CAMPAIGN A FINDING CAME FROM.
//
// **Found by:** names the TARGET. Nothing recorded the RUN, so a report
// scoped to one campaign had to guess from workspace names an author happened
// to type in the prose -- and every report over this directory printed all of
// it under whatever heading it was given, which is how a campaign that built
// no storage engine published eight storage-engine findings.
//
// The field closes that, for findings recorded from here on. It cannot be
// filled backwards for most of what is already here, and this package does
// not pretend otherwise: see CampaignFor.
const CampaignField = "Campaign"

// Campaign is the campaign a write-up records itself against, or "".
func Campaign(md string) string { return Field(md, CampaignField) }

// Unknown is the value written when nothing can establish the campaign.
//
// WRITTEN, not left absent. An absent field and an unanswerable one look the
// same to every reader and to the gate; recording it makes the gap countable
// and gives a person somewhere to put the answer.
const UnknownCampaign = "unknown"

// WorkspaceCampaigns maps a workspace to the campaigns that ran it, from the
// manifests on disk.
//
// ONLY FROM MANIFESTS. A campaign manifest is a record written by the run
// itself; anything else -- a workspace name that resembles a slug, a run that
// used the workspace at some other time -- is a guess, and a guess in a
// provenance field is worse than a blank.
func WorkspaceCampaigns(campaignsRoot string) map[string][]string {
	out := map[string]map[string]bool{}
	add := func(ws, slug string) {
		if ws == "" || slug == "" {
			return
		}
		if out[ws] == nil {
			out[ws] = map[string]bool{}
		}
		out[ws][slug] = true
	}
	for _, pat := range []string{"*/MANIFEST.json", "*/*/MANIFEST.json"} {
		paths, _ := filepath.Glob(filepath.Join(campaignsRoot, pat))
		for _, p := range paths {
			b, err := os.ReadFile(p)
			if err != nil {
				continue
			}
			var m struct {
				Slug       string   `json:"slug"`
				Workspaces []string `json:"workspaces"`
				Entries    []struct {
					Workspace string `json:"workspace"`
				} `json:"entries"`
			}
			if json.Unmarshal(b, &m) != nil {
				continue
			}
			for _, w := range m.Workspaces {
				add(w, m.Slug)
			}
			for _, e := range m.Entries {
				add(e.Workspace, m.Slug)
			}
		}
	}
	res := map[string][]string{}
	for ws, slugs := range out {
		var l []string
		for s := range slugs {
			l = append(l, s)
		}
		sort.Strings(l)
		res[ws] = l
	}
	return res
}

// CampaignFor is the campaign a write-up can be attributed to, and whether it
// could be established at all.
//
// UNAMBIGUOUS ONLY. A write-up is attributed when the workspaces it names
// resolve, through the manifests, to exactly ONE campaign. Naming several
// campaigns is not an attribution -- the finding was seen in more than one
// place, and picking one would invent the answer. Naming none is not either.
//
// This is deliberately far stricter than what could be inferred. A looser rule
// mapped eight of twenty-five findings to a campaign, and every one of those
// eight was wrong: it attributed anything mentioning a workspace to whichever
// runs of that workspace happened to be recorded, which is a coincidence of
// what got archived, not evidence about the defect.
func CampaignFor(workspacesNamed []string, byWS map[string][]string) (string, bool) {
	seen := map[string]bool{}
	for _, ws := range workspacesNamed {
		for _, c := range byWS[ws] {
			seen[c] = true
		}
	}
	if len(seen) != 1 {
		return "", false
	}
	for c := range seen {
		return c, true
	}
	return "", false
}

// MissingCampaign lists findings with no Campaign field at all.
//
// Distinct from one recording "unknown": that is an answer, and this is a
// write-up that never asked the question.
func MissingCampaign(root string) []string {
	ents, err := os.ReadDir(root)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range ents {
		if !e.IsDir() || !isFindingDir(e.Name()) {
			continue
		}
		b, err := os.ReadFile(filepath.Join(root, e.Name(), "README.md"))
		if err != nil || Campaign(string(b)) == "" {
			out = append(out, e.Name())
		}
	}
	sort.Strings(out)
	return out
}
