package wslock

import (
	"errors"
	"strings"
	"testing"
)

// A build REPLACES the directory running fuzzers execute out of, and two
// campaigns on one workspace share a corpus and truncate each other's logs.
// Neither announces itself, so the second worker has to be refused.
func TestSecondHolderIsRefusedAndTheFirstIsNamed(t *testing.T) {
	ws := t.TempDir()

	first, err := Acquire(ws, "campaign")
	if err != nil {
		t.Fatalf("first Acquire: %v", err)
	}
	defer first.Release()

	_, err = Acquire(ws, "build")
	if err == nil {
		t.Fatal("a second holder was allowed onto the same workspace")
	}
	var busy Busy
	if !errors.As(err, &busy) {
		t.Fatalf("err = %v, want Busy", err)
	}
	// The refusal must be actionable: "workspace is in use" with no subject
	// sends people to ps.
	if !strings.Contains(err.Error(), "campaign") {
		t.Errorf("refusal does not name the holder: %v", err)
	}
	if busy.Holder.PID == 0 {
		t.Error("refusal does not carry the holder's pid")
	}
}

// Releasing must let the next one in, or the guard becomes the outage.
func TestReleaseLetsTheNextInAndIsSafeOnNil(t *testing.T) {
	ws := t.TempDir()
	l, err := Acquire(ws, "build")
	if err != nil {
		t.Fatal(err)
	}
	l.Release()

	second, err := Acquire(ws, "sweep")
	if err != nil {
		t.Fatalf("the lock was not released: %v", err)
	}
	second.Release()

	var nilLock *Lock
	nilLock.Release() // callers defer this before knowing they got it
}

// Two different workspaces are independent.
func TestLocksArePerWorkspace(t *testing.T) {
	a, b := t.TempDir(), t.TempDir()
	la, err := Acquire(a, "campaign")
	if err != nil {
		t.Fatal(err)
	}
	defer la.Release()
	lb, err := Acquire(b, "campaign")
	if err != nil {
		t.Fatalf("a lock on one workspace blocked another: %v", err)
	}
	lb.Release()
}

// A campaign holds the workspace lock for the whole run and then spawns
// `pgfuzz build` as a subprocess. That child asked for the same lock and was
// refused, so a campaign could never build a workspace it had locked and
// reported "no workspace built; nothing to fuzz".
func TestAChildInheritsOnlyTheLockItsParentNames(t *testing.T) {
	mine, other := t.TempDir(), t.TempDir()

	parent, err := Acquire(mine, "campaign")
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Release()

	// Without the hand-off, the child is refused -- which was the bug.
	if _, err := Acquire(mine, "build"); err == nil {
		t.Fatal("a second holder was allowed without the hand-off")
	}

	t.Setenv(EnvHeld, mine)

	// The named workspace: allowed, and Release on the nil lock is safe.
	l, err := Acquire(mine, "build")
	if err != nil {
		t.Fatalf("a child was refused its parent's lock: %v", err)
	}
	l.Release()

	// ONLY the named one. An unrelated workspace is still locked normally, or
	// the hand-off would be a way to disable locking generally.
	l2, err := Acquire(other, "build")
	if err != nil {
		t.Fatalf("an unrelated workspace could not be locked: %v", err)
	}
	defer l2.Release()
	if _, err := Acquire(other, "build2"); err == nil {
		t.Error("the hand-off disabled locking for a workspace it did not name")
	}
}
