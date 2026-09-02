package archive

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Manifest is what an archived run says about itself.
//
// Read by `pgfuzz index` to build the campaign history, and by anyone asking
// "what would I have to reproduce". Every field is recorded rather than
// derived later: a fact that has to be reconstructed from a directory name is
// a fact that will be reconstructed wrongly.
type Manifest struct {
	Slug              string                       `json:"slug"`
	RunID             string                       `json:"run_id"`
	ConfigFingerprint string                       `json:"config_fingerprint"`
	ArchivedAt        string                       `json:"archived_at"`
	Host              string                       `json:"host"`
	ToolCommit        string                       `json:"tool_commit"`
	FPVersion         int                          `json:"fp_version"`
	OSSFuzz           Provenance                   `json:"oss_fuzz"`
	Workspaces        []string                     `json:"workspaces"`
	Corpus            map[string]CorpusNote        `json:"corpus"`
	Harness           Harness                      `json:"harness"`
	Fuzzers           map[string]map[string]string `json:"fuzzers"`
	Reproducers       map[string]int               `json:"reproducers"`
	Builds            map[string]json.RawMessage   `json:"builds"`
}

// CorpusNote records what was archived AND whether it was verified.
//
// "verified" is the difference between a tarball and a backup: a tar that
// wrote successfully and a tar whose contents match the count are not the same
// claim, and only the second one means the corpus survived.
type CorpusNote struct {
	Inputs   int    `json:"inputs"`
	Archived int    `json:"archived,omitempty"`
	Verified bool   `json:"verified"`
	Error    string `json:"error,omitempty"`
}

// Harness identifies the fuzzer that produced the numbers.
type Harness struct {
	SourcesSHA256 string `json:"sources_sha256"`
	LastCommit    string `json:"last_commit"`
}

// FuzzerHashes is sha256 of every built target, per workspace.
//
// 172ms per 58MB binary, about four seconds for a full edition -- the cost is
// nothing against being able to say what actually ran.
func FuzzerHashes(ossfuzz string, workspaces []string) map[string]map[string]string {
	out := map[string]map[string]string{}
	for _, ws := range workspaces {
		dir := filepath.Join(ossfuzz, "build", "out", "pgfuzz-"+ws)
		bins, _ := filepath.Glob(filepath.Join(dir, "*_fuzzer"))
		sort.Strings(bins)
		rows := map[string]string{}
		for _, p := range bins {
			if st, err := os.Stat(p); err != nil || st.IsDir() {
				continue
			}
			rows[filepath.Base(p)] = shaFile(p)
		}
		if len(rows) > 0 {
			out[ws] = rows
		}
	}
	return out
}

// ReproducerCounts counts the crash, oom, timeout and leak artifacts kept for
// each workspace.
func ReproducerCounts(wsRoot string, workspaces []string) map[string]int {
	out := map[string]int{}
	for _, ws := range workspaces {
		out[ws] = countReproducers(filepath.Join(wsRoot, ws, "artifacts"))
	}
	return out
}

func countReproducers(dir string) int {
	n := 0
	filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if isReproducer(d.Name()) {
			n++
		}
		return nil
	})
	return n
}

func isReproducer(name string) bool {
	for _, pre := range []string{"crash-", "oom-", "timeout-", "leak-"} {
		if strings.HasPrefix(name, pre) {
			return true
		}
	}
	return false
}

// Builds carries each workspace's BUILD-INFO.json through verbatim.
//
// Verbatim, not re-modelled: the archive's job is to preserve what the build
// recorded, and a struct here would silently drop any field added later.
func Builds(ossfuzz string, workspaces []string) map[string]json.RawMessage {
	out := map[string]json.RawMessage{}
	for _, ws := range workspaces {
		p := filepath.Join(ossfuzz, "build", "out", "pgfuzz-"+ws, "BUILD-INFO.json")
		if b, err := os.ReadFile(p); err == nil && json.Valid(b) {
			out[ws] = json.RawMessage(b)
		}
	}
	return out
}

// Write saves the manifest and checks it parses back.
func (m Manifest) Write(dir string) error {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	p := filepath.Join(dir, "MANIFEST.json")
	if err := os.WriteFile(p, append(b, '\n'), 0o644); err != nil {
		return err
	}
	// Read it back. A manifest that does not parse turns every later reader --
	// the index, a replay, a person -- into a silent no-op.
	raw, err := os.ReadFile(p)
	if err != nil || !json.Valid(raw) {
		return fmt.Errorf("MANIFEST.json is not valid JSON")
	}
	return nil
}

// TarCorpus archives one workspace's corpus and VERIFIES the result.
//
// zstd because the corpora are the bulk of an archive and the only thing in it
// that is slow to rebuild. The verification re-lists the archive and compares
// counts: a tar that exits 0 having written nothing is a backup that does not
// exist, and finding that out at restore time is finding it out too late.
func TarCorpus(wsDir, dest string) CorpusNote {
	want := 0
	filepath.WalkDir(filepath.Join(wsDir, "corpus"), func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			want++
		}
		return nil
	})
	cmd := exec.Command("tar", "-I", "zstd -3 -T4", "-cf", dest, "-C", wsDir, "corpus")
	if err := cmd.Run(); err != nil {
		return CorpusNote{Inputs: want, Error: "tar failed"}
	}
	got := 0
	list := exec.Command("tar", "-I", "zstd -d", "-tf", dest)
	out, err := list.Output()
	if err == nil {
		for _, l := range strings.Split(string(out), "\n") {
			if l != "" && !strings.HasSuffix(l, "/") {
				got++
			}
		}
	}
	if got == want {
		return CorpusNote{Inputs: want, Verified: true}
	}
	return CorpusNote{Inputs: want, Archived: got, Verified: false}
}

// NewManifest assembles everything an archive records about itself.
func NewManifest(slug, stamp, fp, repo, ossfuzz, wsRoot string, workspaces []string,
	base string) Manifest {

	host, _ := os.Hostname()
	return Manifest{
		Slug:              slug,
		RunID:             stamp + "-" + fp,
		ConfigFingerprint: fp,
		ArchivedAt:        time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		Host:              host,
		ToolCommit:        Commit(repo, true),
		FPVersion:         FPVersion,
		OSSFuzz: Provenance{
			Commit: Commit(ossfuzz, false), Dirty: Dirty(ossfuzz), BaseImage: base,
		},
		Workspaces:  workspaces,
		Corpus:      map[string]CorpusNote{},
		Harness:     Harness{HarnessHash(repo), HarnessCommit(repo)},
		Fuzzers:     FuzzerHashes(ossfuzz, workspaces),
		Reproducers: ReproducerCounts(wsRoot, workspaces),
		Builds:      Builds(ossfuzz, workspaces),
	}
}

func shaFile(p string) string {
	f, err := os.Open(p)
	if err != nil {
		return "UNREADABLE"
	}
	defer f.Close()
	h := newSHA()
	if _, err := io.Copy(h, f); err != nil {
		return "UNREADABLE"
	}
	return hexShort(h.Sum(nil), 16)
}

// BuildInfo is what a workspace's build recorded about itself.
//
// The field names are BUILD-INFO.json's own. An earlier version invented "ref"
// and "orioledb_sha", which are not written by anything -- so the provenance
// table rendered an empty ref column beside a real commit, which reads as "the
// ref is unknown" when the truth is that nobody asked for the right key.
// ONE MODEL OF THIS FILE, for the whole tool. Two packages read it and each
// had grown its own struct with its own subset of the keys -- which is how a
// column headed "ref" came to print server_tree: the second model was written
// from memory, and nothing compared it against the first.
type BuildInfo struct {
	PGRefSHA   string            `json:"pg_ref_sha"`
	Sanitizer  string            `json:"sanitizer"`
	ServerTree string            `json:"server_tree"`
	OrioleDB   string            `json:"orioledb"`
	Cassert    bool              `json:"cassert"`
	BuiltAt    string            `json:"built_at"`
	Engine     string            `json:"fuzzing_engine"`
	Plugins    map[string]string `json:"plugins"`
}

// ReadBuildInfo parses one BUILD-INFO.json by path.
func ReadBuildInfo(path string) BuildInfo {
	var bi BuildInfo
	if b, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(b, &bi)
	}
	return bi
}

// ServerTree describes how the SERVER half was built -- "uninstrumented gcc,
// --enable-cassert" -- which is not a ref and must not be printed as one.
//
// The ref a workspace tracks lives in its workspace.conf, because it is
// configuration: which PostgreSQL to test is the experiment, and the build
// output records what came out rather than what was asked for.

// BuildInfoOf reads one workspace's BUILD-INFO.json.
//
// A signature belongs to the TREE it was found in, not to a workspace name.
// Most of these refs move between campaigns -- origin/REL_*_STABLE,
// origin/master, the OrioleDB flavors resolved through .pgtags -- so
// "pg17-head-add" names a different tree every time a campaign rebuilds.
func BuildInfoOf(ossfuzz, ws string) BuildInfo {
	return ReadBuildInfo(filepath.Join(ossfuzz, "build", "out", "pgfuzz-"+ws, "BUILD-INFO.json"))
}
