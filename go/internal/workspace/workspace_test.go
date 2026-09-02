package workspace

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSetReplacesAndPreserves(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "workspace.conf")
	// A value containing '=' -- patch paths and GUCs both do, and splitting on
	// every separator instead of the first truncated them.
	os.WriteFile(p, []byte("# a comment\nname=ws\ngucs=cron.database_name='dbfuzz'\nref=old\n"), 0o644)

	if err := Set(dir, "ref", "REL_17_10"); err != nil {
		t.Fatal(err)
	}
	if err := Set(dir, "sanitizer", "address"); err != nil {
		t.Fatal(err)
	}
	c, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if c.Ref != "REL_17_10" {
		t.Errorf("ref = %q", c.Ref)
	}
	if c.Sanitizer != "address" {
		t.Errorf("sanitizer = %q", c.Sanitizer)
	}
	if got := c.Get("gucs"); got != "cron.database_name='dbfuzz'" {
		t.Errorf("gucs mangled: %q", got)
	}
	if c.Get("name") != "ws" {
		t.Error("unrelated key lost")
	}
	b, _ := os.ReadFile(p)
	if n := len(b); n == 0 {
		t.Fatal("config emptied")
	}
}

func TestKeyFlattensBranchNames(t *testing.T) {
	if got := Key("origin/master", "address", "libfuzzer"); got != "origin-master__address__libfuzzer" {
		t.Errorf("Key = %q", got)
	}
}
