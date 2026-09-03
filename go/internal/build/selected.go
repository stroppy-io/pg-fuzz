package build

import "strings"

// Selected narrows a workspace's built targets to the ones its config asks to
// run.
//
// A KNOB THAT DID NOTHING. Every workspace.conf on this host carries
//
//	# Targets to run when you ask for "all".  Empty means every built target.
//	targets=
//
// written there by the driver that created the workspace -- and neither that
// driver nor this one ever read it back. All 59 are empty, so nothing has been
// wrong yet; the first person to fill one in would have been ignored silently,
// which is worse than the key not existing.
//
// Empty means every built target, as the comment in the file promises.
//
// A name that is listed but was not built is DROPPED, not invented: a config
// cannot conjure a binary, and running a target that is not there is not a
// thing this can do. The caller is told which ones went missing so the
// difference between "I asked for four and got four" and "I asked for four and
// three exist" is visible rather than inferred from a count.
func Selected(built []string, want string) (selected, missing []string) {
	names := strings.Fields(want)
	if len(names) == 0 {
		return built, nil
	}
	have := make(map[string]bool, len(built))
	for _, t := range built {
		have[t] = true
	}
	// The CONFIG's order, because it is the order somebody wrote down.
	for _, n := range names {
		if have[n] {
			selected = append(selected, n)
		} else {
			missing = append(missing, n)
		}
	}
	return selected, missing
}
