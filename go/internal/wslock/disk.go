package wslock

import (
	"fmt"
	"syscall"
)

// FreeGB is how much room is left where this path lives.
func FreeGB(path string) (float64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, err
	}
	return float64(st.Bavail) * float64(st.Bsize) / (1 << 30), nil
}

// NeedDisk refuses work that has nowhere to write.
//
// A build writes a PostgreSQL tree TWICE plus docker layers, and a campaign
// grows corpora continuously. Running out part-way does not fail where the
// cause is: ENOSPC surfaces as an unrelated write failing much later, and it
// can truncate a corpus mid-write. The old driver refused below 15 GB for a
// build and armed a watchdog at a floor during a run; the port had no Statfs
// outside the dashboard.
func NeedDisk(path string, wantGB float64, what string) error {
	free, err := FreeGB(path)
	if err != nil {
		// FAIL CLOSED, as the shell did. `disk_free_gb` returning empty
		// became ${f:-0} and died -- because this is the CHEAP tier: refusing
		// to start costs a retry, and the thing it prevents is an ENOSPC
		// hours later that truncates a corpus which took days to evolve.
		//
		// The running floor still fails open, and deliberately: killing a
		// slice already in flight on a reading that could not be taken throws
		// away work for no evidence. The two tiers differ here because their
		// costs differ.
		return fmt.Errorf("cannot read free space where %s writes (%v)"+
			" -- refusing to start %s; pass -no-disk-check to override", path, err, what)
	}
	if free < wantGB {
		return fmt.Errorf("%.1f GB free where %s writes, need %.0f GB for %s"+
			" -- free space or pass -no-disk-check",
			free, path, wantGB, what)
	}
	return nil
}
