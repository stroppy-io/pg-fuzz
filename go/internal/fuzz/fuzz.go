// Package fuzz runs a built target.
//
// THREE THINGS HERE ARE NOT OBVIOUS AND ALL THREE WERE PAID FOR
// =============================================================
//
// The OVERLAY. /out is mounted read-only as the lower layer of an overlayfs
// whose upper layer is per-run. Without it two concurrent runs share one /out
// and libFuzzer's artifact writes race; the coverage script wipes shared
// output directories at startup, so parallel runs destroyed each other's
// profile data. The overlay makes each run's writes private while the build
// underneath stays untouched.
//
// The DURABLE LOG, written inside the container onto a bind mount. The host
// side pipes through tee, but stdout is the fragile copy: a killed process
// loses whatever is buffered and one broken pipe loses everything. libFuzzer
// deletes its own fuzz-<i>.log once it has printed them, so a file on a bind
// mount is the only record that survives a kill -- and campaigns here get
// killed mid-slice routinely.
//
// -max_len, stated rather than left to libFuzzer. Without it libFuzzer picks
// 4096 cold but silently adopts the largest corpus entry once a corpus exists,
// so the effective limit drifts upward as the corpus accumulates and two runs
// of "the same" target are not comparable.
package fuzz

import (
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"pgfuzz/internal/logs"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

// Request is one fuzzing slice.
// DefaultStopFreeGB is the floor the shell driver used: below this, a running
// slice is stopped. Losing one target's round beats losing the filesystem.
//
// DefaultPreflightGB is the other tier: refuse to START below it. Deliberately
// higher, because refusing costs nothing -- reclaim and retry -- while killing
// a running slice costs its round.
const (
	DefaultStopFreeGB  = 8
	DefaultPreflightGB = 15
)

// HangGrace is how long past its own budget a slice may run before it is
// stopped.
//
// A SLICE HAD NO UPPER BOUND AT ALL. libFuzzer is given -max_total_time, and
// honours it by checking the clock between executions -- so a single input
// that never returns runs forever, and `docker run` with it. The campaign then
// waits on that slice for the rest of the run: not a crash, not a timeout in
// the series, just a workspace that stops producing and a driver that looks
// alive.
//
// The shell driver caught this from OUTSIDE, with a watchdog process that
// killed containers past their budget. That was ported -- `pgfuzz watchdog` --
// and nothing ever starts it, so it guards only the runs where somebody
// remembered to open a second terminal. The bound belongs where the run is.
//
// Five minutes, matching the watchdog's grace: long enough that a slow
// shutdown or a final corpus write is not mistaken for a hang.
const HangGrace = 5 * time.Minute

type Request struct {
	Workspace string // the workspace directory
	// Data is where the corpus, artifacts, lineage and run scratch live.
	// Empty means Workspace, which is what a standalone `pgfuzz run` wants.
	// A CAMPAIGN sets it to its own directory: the corpus that produced a
	// campaign's coverage has to travel with the campaign, or the slug cannot
	// be moved and re-measured, which is the whole point of the slug.
	Data    string
	Name    string // workspace name, for the container name
	OutDir  string // the build, mounted read-only under the overlay
	Target  string
	Seconds int
	Jobs    int
	MaxLen  int

	// StopFreeGB kills a RUNNING slice when free space falls through it.
	//
	// THE SECOND TIER. The shell driver had two deliberately different
	// thresholds: a preflight that refuses to START (cheap to honour --
	// reclaim and retry) and a floor that kills a slice already running,
	// because losing one target's round beats losing the filesystem. The port
	// carried the preflight into builds and the floor into coverage, and left
	// the fuzz path with neither. A campaign is exactly what fills a disk: it
	// grows corpora continuously for hours, and ENOSPC mid-write can truncate
	// a corpus that took days to evolve.
	//
	// Zero disarms it.
	StopFreeGB float64
	Sanitizer  string
	Lineage    bool
	Image      string
	Stream     io.Writer
}

// Result is what the slice produced.
type Result struct {
	// Target the result belongs to. A sweep returns a slice of these and the
	// caller could not say which was which, so anything reported per-target
	// had to be inferred from position -- which stops being true the moment a
	// target is skipped.
	Target     string
	Elapsed    time.Duration
	LogPath    string
	CorpusFrom int
	CorpusTo   int

	// ARTIFACTS BEFORE AND AFTER, like the corpus, because the directory
	// accumulates. Reporting the total as this slice's output turns weeks of
	// history into "this run found 22 crashes" -- which is exactly the
	// artifact-versus-finding confusion the reports spend a section
	// correcting, arriving through the dashboard instead.
	ArtifactsFrom int
	ArtifactsTo   int
	// DiskStop is whether the disk floor stopped this slice. It must reach
	// the series: a slice cut short by the filesystem produced fewer
	// executions for a reason that has nothing to do with the target, and a
	// ratchet comparing it against a full slice would call that a regression.
	DiskStop bool
	// Hung is whether the slice was stopped for running past its own budget.
	// It is a fact about the TARGET -- one input that never returns -- and
	// belongs in the record, unlike a disk stop, which is a fact about the
	// machine.
	Hung bool
	// Harvested is how many reproducers this run moved out of the scratch
	// overlay. Recorded separately from the artifacts delta so "found three"
	// and "the directory happens to hold three more" stay distinguishable.
	Harvested int
	// Dict is whether libFuzzer was given a dictionary for this slice.
	Dict     bool
	ExitCode int
}

// NewArtifacts is what THIS slice produced.
func (r Result) NewArtifacts() int {
	if n := r.ArtifactsTo - r.ArtifactsFrom; n > 0 {
		return n
	}
	return 0
}

// The container runs THIS BINARY, not a generated shell script. See
// internal/incontainer.

// Run fuzzes one target for one slice.
// freeGB is how much room is left where a path lives.
func freeGB(path string) (float64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, err
	}
	return float64(st.Bavail) * float64(st.Bsize) / (1 << 30), nil
}

func Run(ctx context.Context, r Request) (Result, error) {
	if r.MaxLen == 0 {
		r.MaxLen = 4096
	}
	if r.Jobs == 0 {
		r.Jobs = 1
	}
	if r.Image == "" {
		r.Image = "gcr.io/oss-fuzz-base/base-runner:ubuntu-24-04"
	}

	self, err := os.Executable()
	if err != nil {
		return Result{}, fmt.Errorf("cannot find my own binary to mount: %w", err)
	}
	if real, err := filepath.EvalSymlinks(self); err == nil {
		self = real
	}

	bin := filepath.Join(r.OutDir, r.Target)
	if fi, err := os.Stat(bin); err != nil || fi.Mode()&0o111 == 0 {
		return Result{}, fmt.Errorf("no such target: %s", r.Target)
	}

	data := r.Data
	if data == "" {
		data = r.Workspace
	}
	corpus := filepath.Join(data, "corpus", r.Target)
	arts := filepath.Join(data, "artifacts", r.Target)
	lineage := filepath.Join(data, "lineage")
	rundir := filepath.Join(data, "runtmp", r.Target)
	for _, d := range []string{corpus, arts, lineage,
		filepath.Join(rundir, "upper"), filepath.Join(rundir, "work")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return Result{}, err
		}
	}
	// A previous run's overlay must not be reused: its upper layer still holds
	// that run's artifacts, and they would be attributed to this one.
	os.RemoveAll(filepath.Join(rundir, "upper"))
	os.RemoveAll(filepath.Join(rundir, "work"))
	os.MkdirAll(filepath.Join(rundir, "upper"), 0o755)
	os.MkdirAll(filepath.Join(rundir, "work"), 0o755)

	before := countFiles(corpus)
	artsBefore := countArtifacts(arts)
	stamp := time.Now().Format("20060102-150405")
	logPath := filepath.Join(arts, "run-"+stamp+".log")

	lineageArg := ""
	if r.Lineage {
		lineageArg = "/lineage/" + r.Target + "-" + stamp + ".tsv"
	}

	name := fmt.Sprintf("pgfuzz-run-%s-%s-%d", r.Name, r.Target, os.Getpid())
	args := []string{
		"run", "--privileged", "--shm-size=2g", "--platform", "linux/amd64", "--rm",
		"--name", name,
		"-e", "FUZZING_ENGINE=libfuzzer",
		"-e", "SANITIZER=" + r.Sanitizer,
		"-e", "RUN_FUZZER_MODE=interactive",
		"-e", "HELPER=True",
		"-e", "CORPUS_DIR=/tmp/" + r.Target + "_corpus",
		"-e", "LD_LIBRARY_PATH=/out/tmp_install/usr/local/pgsql/lib",
		"-e", "PGFUZZ_LINEAGE=" + lineageArg,
		// The container runs as root; without this it leaves the lineage TSVs
		// and the run scratch root-owned on the host.
		"-e", fmt.Sprintf("PGFUZZ_UID=%d:%d", os.Getuid(), os.Getgid()),
		"-v", corpus + ":/tmp/" + r.Target + "_corpus",
		"-v", lineage + ":/lineage",
		"-v", r.OutDir + ":/out-lower:ro",
		"-v", rundir + ":/run-ovl",
		// The binary mounts itself in and re-executes. It is static and
		// CGO-free, so it runs in any Linux image.
		"-v", self + ":/pgfuzz:ro",
		"--entrypoint", "/pgfuzz",
		r.Image, "_fuzz", r.Target,
		"-max_total_time=" + strconv.Itoa(r.Seconds),
	}
	if r.Jobs > 1 {
		args = append(args,
			"-jobs="+strconv.Itoa(r.Jobs),
			"-workers="+strconv.Itoa(r.Jobs))
	}
	args = append(args,
		"-max_len="+strconv.Itoa(r.MaxLen),
		"-detect_leaks=0",
		"-artifact_prefix=/out/",
		"-print_final_stats=1")

	lf, err := os.Create(logPath)
	if err != nil {
		return Result{}, err
	}
	defer lf.Close()
	var sink io.Writer = lf
	if r.Stream != nil {
		sink = io.MultiWriter(lf, r.Stream)
	}

	// THE HARD DEADLINE, and the disk floor, share one guard.
	//
	// docker stop rather than killing the docker CLI: exec.CommandContext
	// would kill the client and leave the container running, which is how a
	// "timed out" slice keeps a core busy for the rest of the campaign.
	// Stopping sends SIGTERM first, so libFuzzer prints the final stats this
	// slice is judged on before it goes.
	hardStop := time.Duration(r.Seconds)*time.Second + HangGrace

	// THE DISK FLOOR, armed for as long as the slice runs.
	//
	// docker stop on THIS container by name, not a kill by ancestor image: a
	// campaign runs several slices at once and the others have done nothing
	// wrong. Stopping is enough -- libFuzzer's corpus is already on disk, and
	// the harvest below still runs.
	stopGuard := make(chan struct{})
	var diskStopped, hung atomic.Bool
	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		deadline := time.After(hardStop)
		for {
			select {
			case <-stopGuard:
				return
			case <-deadline:
				hung.Store(true)
				fmt.Fprintf(os.Stderr,
					"pgfuzz: %s ran %s past its %ds budget -- stopping it\n",
					name, HangGrace, r.Seconds)
				// -t 20: SIGTERM, then twenty seconds for the final stats.
				exec.Command("docker", "stop", "-t", "20", name).Run()
				return
			case <-t.C:
				if r.StopFreeGB <= 0 {
					continue
				}
				free, err := freeGB(data)
				if err != nil || free >= r.StopFreeGB {
					continue
				}
				diskStopped.Store(true)
				fmt.Fprintf(os.Stderr,
					"pgfuzz: only %.1f GB free where %s writes -- stopping %s\n",
					free, data, name)
				exec.Command("docker", "stop", "-t", "5", name).Run()
				return
			}
		}
	}()

	cmd := exec.CommandContext(ctx, "docker", args...)
	cmd.Stdout, cmd.Stderr = sink, sink
	start := time.Now()
	runErr := cmd.Run()
	close(stopGuard)

	res := Result{
		Target:     r.Target,
		Elapsed:    time.Since(start),
		LogPath:    logPath,
		CorpusFrom: before,
		CorpusTo:   countFiles(corpus),
		DiskStop:   diskStopped.Load(),
		Hung:       hung.Load(),
	}

	// HARVEST THE REPRODUCERS BEFORE ANYTHING ELSE LOOKS AT THE COUNTS.
	//
	// libFuzzer writes artifacts to -artifact_prefix=/out/, and /out is the
	// overlay whose upper layer is per-run scratch that the NEXT run of this
	// target deletes. So a reproducer was written to a directory designed to
	// be thrown away, and ArtifactsTo counted artifacts/<target>/, which the
	// fuzzer never writes to -- meaning every run reported "artifacts +0"
	// however many crashes it found. On the campaign that caught this, six
	// reproducers were sitting in scratch while the series said zero across
	// 103 slices.
	//
	// Moved, not copied, and before the counts are taken.
	// The processor seconds the container measured of itself, placed beside
	// the log so ratchet.CPUSecs finds it. It had a reader and no writer, so
	// the report silently fell back to allocated core-time -- the number its
	// own comment was written to stop being quoted.
	// The per-worker logs, beside the slice's own. Named so the round they
	// belong to is obvious and the next slice cannot clobber them.
	if m, _ := filepath.Glob(filepath.Join(rundir, "fuzz-*.log")); len(m) > 0 {
		for _, p := range m {
			if b, err := os.ReadFile(p); err == nil {
				os.WriteFile(filepath.Join(arts,
					"run-"+stamp+"-"+filepath.Base(p)), b, 0o644)
			}
		}
	}

	if b, err := os.ReadFile(filepath.Join(rundir, "run.cpu")); err == nil {
		os.WriteFile(strings.TrimSuffix(logPath, ".log")+".cpu", b, 0o644)
	}

	if reg, err := logs.ParseRegime(logPath); err == nil {
		res.Dict = reg.Dict
	}
	res.Harvested = harvest(filepath.Join(rundir, "upper"), arts)

	// COMPRESSED, as the shell compressed it -- these run to gigabytes and
	// gzip takes about fifty to one on them. Safe now that every reader
	// handles both forms; before that it would have blinded the ratchet, the
	// gate and the census at once.
	if err := gzipInPlace(logPath); err == nil {
		res.LogPath = logPath + ".gz"
	}
	res.ArtifactsFrom = artsBefore
	res.ArtifactsTo = countArtifacts(arts)
	if ee, ok := runErr.(*exec.ExitError); ok {
		res.ExitCode = ee.ExitCode()
	}
	// A non-zero exit is normal: libFuzzer returns non-zero when it finds a
	// crash, which is the point. The caller judges by what landed on disk.
	return res, nil
}

func countFiles(dir string) int {
	n := 0
	ents, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}
	for _, e := range ents {
		if !e.IsDir() {
			n++
		}
	}
	return n
}

func countArtifacts(dir string) int {
	n := 0
	ents, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}
	for _, e := range ents {
		switch {
		case len(e.Name()) > 6 && e.Name()[:6] == "crash-",
			len(e.Name()) > 5 && e.Name()[:5] == "leak-",
			len(e.Name()) > 4 && e.Name()[:4] == "oom-",
			len(e.Name()) > 8 && e.Name()[:8] == "timeout-":
			n++
		}
	}
	return n
}

// SweepRequest is one pass over every target.
type SweepRequest struct {
	Request // Target is filled in per target
	Targets []string
	Rotate  int // rotate the order by this much; the round number
	// Budgets is the tuned per-target time table. Empty means every target
	// gets Request.Seconds.
	//
	// THE SHELL APPLIED THIS PER TARGET IN EVERY SWEEP, not only in a soak:
	// spi_query_fuzzer and simple_query_fuzzer need 150s and 200s before they
	// are past corpus replay. The port consumed the table in soak alone, so
	// every campaign round gave those two the flat -time and produced their
	// exec counts on a different time basis than the floors they are judged
	// against -- and `corpus -autocap -tune-budget` kept writing a table
	// nothing read.
	Budgets  Budgets
	Deadline time.Time
	OnStart  func(target string, i, n int)
	OnDone   func(target string, r Result)
}

// Sweep runs every target once.
//
// ROTATED BY THE ROUND NUMBER, and that is not cosmetic. A sweep cut short by
// a deadline stops where it is, and a fixed order means it always stops in the
// same place -- on 2026-08-31 oriolebare18-add ran 20 of 23 and lost
// spi_query, tsearch and xlogreader, the alphabetical tail, while every arm
// that finished kept all 23. spi_query_fuzzer is the highest-yield target in
// this tree and it is third from the end. Rotating by the round makes the loss
// land somewhere different each time, deterministically, so two rounds stay
// comparable.
func Sweep(ctx context.Context, sr SweepRequest) ([]Result, error) {
	targets := append([]string(nil), sr.Targets...)
	if n := len(targets); n > 1 && sr.Rotate != 0 {
		off := ((sr.Rotate % n) + n) % n
		targets = append(targets[off:], targets[:off]...)
	}
	var out []Result
	for i, t := range targets {
		if !sr.Deadline.IsZero() && time.Now().After(sr.Deadline) {
			// Short, and the caller is told by the count rather than left to
			// infer it from a log.
			break
		}
		if err := ctx.Err(); err != nil {
			return out, err
		}
		req := sr.Request
		req.Target = t
		req.Seconds = sr.Budgets.For(sr.Name, t, sr.Request.Seconds)
		if sr.OnStart != nil {
			sr.OnStart(t, i+1, len(targets))
		}
		res, err := Run(ctx, req)
		if err != nil {
			return out, fmt.Errorf("%s: %w", t, err)
		}
		if sr.OnDone != nil {
			sr.OnDone(t, res)
		}
		out = append(out, res)
	}
	return out, nil
}

// artifactPrefixes are what libFuzzer names a saved input, by kind.
var artifactPrefixes = []string{"crash-", "leak-", "timeout-", "oom-"}

// harvest moves libFuzzer's saved inputs out of the run's scratch overlay and
// into the workspace's artifacts directory, where everything else looks for
// them. Returns how many it moved.
//
// Top level only: the overlay's upper layer also contains run_fuzzer's
// <target>_<engine>_<sanitizer>_out directory and whatever else the container
// touched under /out, none of which is evidence.
func harvest(upper, arts string) int {
	ents, err := os.ReadDir(upper)
	if err != nil {
		return 0
	}
	moved := 0
	for _, e := range ents {
		if e.IsDir() {
			continue
		}
		keep := false
		for _, p := range artifactPrefixes {
			if strings.HasPrefix(e.Name(), p) {
				keep = true
				break
			}
		}
		if !keep {
			continue
		}
		from := filepath.Join(upper, e.Name())
		to := filepath.Join(arts, e.Name())
		if _, err := os.Stat(to); err == nil {
			os.Remove(from) // already harvested by an earlier run
			continue
		}
		if err := os.Rename(from, to); err != nil {
			// Across devices, or a permission the container left behind:
			// copy rather than lose it.
			if b, rerr := os.ReadFile(from); rerr == nil {
				if os.WriteFile(to, b, 0o644) == nil {
					os.Remove(from)
					moved++
				}
			}
			continue
		}
		moved++
	}
	return moved
}

// gzipInPlace compresses a finished log and removes the original.
//
// Only when it succeeds: a half-written .gz beside a deleted .log would lose
// the slice's only durable record, which is the thing the log exists to be.
func gzipInPlace(path string) error {
	in, err := os.Open(path)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp := path + ".gz.partial"
	out, err := os.Create(tmp)
	if err != nil {
		return err
	}
	zw := gzip.NewWriter(out)
	if _, err := io.Copy(zw, in); err != nil {
		zw.Close()
		out.Close()
		os.Remove(tmp)
		return err
	}
	if err := zw.Close(); err != nil {
		out.Close()
		os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path+".gz"); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Remove(path)
}
