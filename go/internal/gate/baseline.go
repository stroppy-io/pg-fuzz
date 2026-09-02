package gate

import (
	"bufio"
	"os"
	"strings"
)

// LoadAccepted reads scripts/ubsan-baseline.tsv.
//
// Configuration, not payload: a person accepting a site, in a commit, with a
// reason, must not require a new binary. The file is read from wherever the
// caller points; nothing here is embedded.
func LoadAccepted(path string) ([]Accepted, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []Accepted
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(strings.TrimSpace(line), "#") || strings.TrimSpace(line) == "" {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) < 4 {
			continue
		}
		out = append(out, Accepted{
			Function: strings.TrimSpace(f[0]),
			Scope:    strings.Split(strings.TrimSpace(f[1]), ","),
			Site:     strings.TrimSpace(f[2]),
			Class:    strings.TrimSpace(f[3]),
		})
	}
	return out, sc.Err()
}
