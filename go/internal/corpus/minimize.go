package corpus

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"time"
)

// MIN OPTIONS -- the two reductions, which are not equally defensible.
//
// A corpus can grow until REPLAYING it outlasts -max_total_time. libFuzzer then
// spends the whole budget in ReadAndExecuteSeedCorpora, never reaches the
// mutation loop, and adds no new units -- so the corpus cannot grow, the next
// round replays the same files, and the target is locked out permanently while
// every activity-based check reads it as healthy. The starvation gate detects
// that state (INITED == DONE); this is the repair.
type MinOptions struct {
	// MaxLen bounds what -merge=1 will consider, and doubles as the size above
	// which an input is archived: spi_query_fuzzer returns immediately for
	// size > MAX_QUERY_LEN, so those inputs NEVER EXECUTE. Dropping them costs
	// no coverage and mutation cannot regenerate them under -max_len either.
	MaxLen int
	RSS    int // rss_limit_mb for the merge

	// Cap, when > 0, bounds the number of inputs KEPT.
	//
	// Merging alone does not bound replay COST: -merge=1 keeps one input per
	// coverage feature, and feature-rich inputs are the expensive ones, so a
	// merged corpus can be 4x smaller and barely faster. spi_query_fuzzer went
	// 17,798 -> 4,430 inputs while throughput fell 150 -> 50 execs/s.
	//
	// Keeping the SMALLEST is a heuristic and should be read as one: for a SQL
	// target, shorter inputs generally parse, plan and execute in less time.
	// It is not a measurement, and it does discard earned coverage -- which is
	// why it runs only after the free drop and only when the cap is exceeded.
	Cap     int
	CapOnly bool // cap an already-merged corpus without re-merging
	Image   string
	Log     io.Writer
}

// MinResult is what happened to one target.
type MinResult struct {
	Target          string
	Before, After   int
	Archived        int
	Backup          string // where the previous corpus went, "" if untouched
	Skipped, Reason string
}

const mergeImage = "gcr.io/oss-fuzz-base/base-runner:ubuntu-24-04"

// Minimize shrinks one target's corpus to the smallest set that preserves its
// coverage features.
//
// -merge=1 keeps one input per coverage feature and drops the rest, so features
// are preserved by construction. It is NOT a heuristic prune.
//
// NOTHING IS DELETED. The old corpus is RENAMED aside; the capped inputs are
// MOVED to a dated backup. An earlier version of the cap path used deletion,
// and that asymmetry cost 126,650 protocol_fuzzer inputs on a diagnosis that
// turned out to be wrong -- the target was deadlocked, not slow. A merge was
// reversible and a cap was not, which is exactly backwards: the cap is the
// cruder judgement of the two.
func Minimize(wsDir, buildDir, target string, o MinOptions) (MinResult, error) {
	res := MinResult{Target: target}
	if o.MaxLen == 0 {
		o.MaxLen = 4096
	}
	if o.RSS == 0 {
		o.RSS = 2560
	}
	if o.Image == "" {
		o.Image = mergeImage
	}
	if o.Log == nil {
		o.Log = io.Discard
	}

	src := filepath.Join(wsDir, "corpus", target)
	if !isDir(src) {
		res.Skipped = "no corpus dir"
		return res, nil
	}
	if _, err := os.Stat(filepath.Join(buildDir, target)); err != nil {
		res.Skipped = "no binary in the build dir"
		return res, nil
	}
	res.Before = countFiles(src)
	if res.Before == 0 {
		res.Skipped = "corpus is empty"
		return res, nil
	}

	// Scratch and backups live OUTSIDE corpus/, because corpus/ is enumerated
	// as the list of targets -- anything parked there is counted as one, and
	// its file count is added to the workspace total that decides plateau.
	backups := filepath.Join(wsDir, "corpus-backups")
	if err := os.MkdirAll(backups, 0o755); err != nil {
		return res, err
	}

	if o.CapOnly {
		// A second merge would find no reduction, refuse the swap, and never
		// reach the cap -- so capping an already-merged corpus is its own mode.
		n, bak, err := applyCap(src, backups, target, o)
		res.Archived, res.Backup, res.After = n, bak, countFiles(src)
		return res, err
	}

	name := fmt.Sprintf(".%s.min.%d", target, os.Getpid())
	dst := filepath.Join(backups, name)
	os.RemoveAll(dst)
	if err := os.MkdirAll(dst, 0o755); err != nil {
		return res, err
	}

	cmd := exec.Command("docker", "run", "--rm",
		"-v", buildDir+":/out",
		"-v", filepath.Join(wsDir, "corpus")+":/corpus",
		"-v", backups+":/backups",
		o.Image,
		"/out/"+target, "-merge=1",
		fmt.Sprintf("-max_len=%d", o.MaxLen),
		fmt.Sprintf("-rss_limit_mb=%d", o.RSS),
		"/backups/"+name, "/corpus/"+target)
	cmd.Stdout, cmd.Stderr = o.Log, o.Log
	if err := cmd.Run(); err != nil {
		os.RemoveAll(dst)
		res.Reason = "merge failed; corpus untouched"
		return res, err
	}

	// libFuzzer ran the merge as root, so everything it just wrote into the
	// corpus is root-owned. Hand it back before anything else looks at it.
	if _, err := Repair(dst); err != nil {
		o.Log.Write([]byte("minimize: " + err.Error() + "\n"))
	}

	after := countFiles(dst)
	// A merge that keeps nothing, or keeps everything, is not worth swapping
	// in -- and an empty result would destroy the target's whole corpus.
	switch {
	case after == 0:
		os.RemoveAll(dst)
		res.After = res.Before
		res.Reason = "merge produced 0 inputs; refusing to swap"
		return res, nil
	case after >= res.Before:
		os.RemoveAll(dst)
		res.After = res.Before
		res.Reason = fmt.Sprintf("merge kept %d of %d (no reduction); corpus untouched", after, res.Before)
		return res, nil
	}

	// Rename, never delete. Two renames, microseconds apart.
	prev := filepath.Join(backups, fmt.Sprintf("%s.premin.%s", target, stamp()))
	if err := os.Rename(src, prev); err != nil {
		os.RemoveAll(dst)
		return res, fmt.Errorf("cannot move the old corpus aside: %w", err)
	}
	if err := os.Rename(dst, src); err != nil {
		return res, fmt.Errorf("SWAP FAILED -- the old corpus is at %s: %w", prev, err)
	}
	res.Backup = prev

	n, capBak, err := applyCap(src, backups, target, o)
	res.Archived = n
	if capBak != "" {
		res.Backup = res.Backup + " and " + capBak
	}
	res.After = countFiles(src)
	return res, err
}

// applyCap performs the two drops, in order of how defensible they are.
func applyCap(src, backups, target string, o MinOptions) (archived int, backup string, err error) {
	if o.Cap <= 0 {
		return 0, "", nil
	}
	bak := filepath.Join(backups, fmt.Sprintf("%s.capped.%s", target, stamp()))
	if err := os.MkdirAll(bak, 0o755); err != nil {
		return 0, "", err
	}
	// Leave no empty directory behind when nothing was archived.
	defer func() {
		if archived == 0 {
			os.Remove(bak)
			backup = ""
		}
	}()

	type ent struct {
		path string
		size int64
	}
	var files []ent
	ents, err := os.ReadDir(src)
	if err != nil {
		return 0, "", err
	}
	for _, e := range ents {
		if e.IsDir() {
			continue
		}
		fi, err := e.Info()
		if err != nil {
			continue
		}
		files = append(files, ent{filepath.Join(src, e.Name()), fi.Size()})
	}

	// 1. Over MaxLen: never executed, so free to drop.
	kept := files[:0]
	for _, f := range files {
		if f.size > int64(o.MaxLen) {
			if os.Rename(f.path, filepath.Join(bak, filepath.Base(f.path))) == nil {
				archived++
			}
			continue
		}
		kept = append(kept, f)
	}
	files = kept

	// 2. Still over the cap: keep the smallest. A heuristic, and it does
	//    discard earned coverage.
	if len(files) > o.Cap {
		sort.Slice(files, func(i, j int) bool { return files[i].size < files[j].size })
		for _, f := range files[o.Cap:] {
			if os.Rename(f.path, filepath.Join(bak, filepath.Base(f.path))) == nil {
				archived++
			}
		}
	}
	return archived, bak, nil
}

func stamp() string { return time.Now().Format("20060102-150405") }

func isDir(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.IsDir()
}

func countFiles(dir string) int {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}
	n := 0
	for _, e := range ents {
		if !e.IsDir() {
			n++
		}
	}
	return n
}
