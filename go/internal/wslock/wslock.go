// Package wslock keeps two things from using one workspace at once.
//
// WHY THIS IS NOT PARANOIA. A build REPLACES the directory that running
// fuzzers are executing out of, and a campaign grows a corpus that a second
// campaign would grow at the same time -- so a rebuild during a sweep swaps
// binaries under a live container, and two campaigns on one workspace share a
// corpus and truncate each other's per-target logs. Neither announces itself:
// the run keeps going, the numbers keep arriving, and the results belong to no
// single experiment.
//
// The old driver had this at two granularities and refused rather than warned.
// The port dropped it, leaving one flock over the ratchet baseline file.
//
// NON-BLOCKING, always. A build that waits for a twelve-hour campaign is a
// build nobody meant to start; the answer is to say what holds the lock and
// let the person decide.
package wslock

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// Holder is what the lock file records, so a refusal can name the process
// rather than just decline.
type Holder struct {
	PID     int    `json:"pid"`
	What    string `json:"what"`
	Started string `json:"started"`
}

// Lock is a held workspace lock.
type Lock struct {
	fd   int
	path string
}

// Busy reports that something else holds the lock, and who.
type Busy struct{ Holder Holder }

func (b Busy) Error() string {
	return fmt.Sprintf("workspace is in use: %s (pid %d, since %s)",
		b.Holder.What, b.Holder.PID, b.Holder.Started)
}

// Acquire takes the workspace lock, or returns Busy naming the holder.
//
// The lock is advisory and per-directory: `<ws>/.pgfuzz.lock`. what describes
// the work ("build", "sweep", "campaign") because "workspace is in use" with
// no subject sends people to `ps`.
func Acquire(wsDir, what string) (*Lock, error) {
	path := filepath.Join(wsDir, ".pgfuzz.lock")
	fd, err := syscall.Open(path, syscall.O_CREAT|syscall.O_RDWR, 0o644)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		// Read who holds it BEFORE giving up, so the refusal is actionable.
		h := read(path)
		syscall.Close(fd)
		if !alive(h.PID) && h.PID != 0 {
			// A stale record from a killed process. The flock itself is the
			// authority -- if it is still held the owner is alive whatever
			// the file says -- so this only improves the message.
			h.What += " (recorded holder is gone; the lock is still held)"
		}
		return nil, Busy{Holder: h}
	}
	b, _ := json.Marshal(Holder{
		PID: os.Getpid(), What: what,
		Started: time.Now().UTC().Format(time.RFC3339),
	})
	syscall.Ftruncate(fd, 0)
	syscall.Pwrite(fd, b, 0)
	return &Lock{fd: fd, path: path}, nil
}

// Release drops the lock. Safe on a nil lock so callers can defer it.
func (l *Lock) Release() {
	if l == nil {
		return
	}
	syscall.Flock(l.fd, syscall.LOCK_UN)
	syscall.Close(l.fd)
}

func read(path string) Holder {
	var h Holder
	if b, err := os.ReadFile(path); err == nil {
		json.Unmarshal(b, &h)
	}
	return h
}

// alive reports whether a pid still exists. Signal 0 tests for existence
// without delivering anything.
func alive(pid int) bool {
	if pid <= 0 {
		return false
	}
	return syscall.Kill(pid, 0) == nil
}
