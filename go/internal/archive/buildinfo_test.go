package archive

import (
	"os"
	"path/filepath"
	"testing"
)

// THE FIELD MUST HAVE THE TYPE THE FILE WRITES.
//
// orioledb is a bool in every BUILD-INFO.json on this host -- 32 false, 8 true
// -- and was declared here as a string. Every read hit an UnmarshalTypeError,
// which ReadBuildInfo discards, so the field came back empty and the census
// provenance table recorded no OrioleDB build for any workspace.
//
// The rest of the struct still populated, which is why nothing looked wrong:
// encoding/json keeps going after a field-level type error and returns it at
// the end, where it was thrown away.
func TestBuildInfoParsesTheFileAsWritten(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "BUILD-INFO.json")
	err := os.WriteFile(p, []byte(`{
	  "pg_ref_sha": "4639b6cfe3f310b71e1e227dd2a915b053992c9b",
	  "sanitizer": "address",
	  "orioledb": true,
	  "cassert": true,
	  "fuzzing_engine": "libfuzzer",
	  "plugins": {"pgaudit": "538f89a"}
	}`), 0o644)
	if err != nil {
		t.Fatal(err)
	}

	bi := ReadBuildInfo(p)
	if !bi.OrioleDB {
		t.Error("orioledb:true did not parse; the field type does not match the file")
	}
	if bi.PGRefSHA == "" || bi.Sanitizer != "address" {
		t.Errorf("the rest of the record did not parse: %+v", bi)
	}
	if bi.Plugins["pgaudit"] != "538f89a" {
		t.Errorf("plugin pins did not parse: %v", bi.Plugins)
	}

	// The common case, and the one that was silently wrong.
	if err := os.WriteFile(p, []byte(`{"pg_ref_sha":"abc","orioledb":false}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if bi := ReadBuildInfo(p); bi.OrioleDB || bi.PGRefSHA != "abc" {
		t.Errorf("orioledb:false record parsed wrong: %+v", bi)
	}
}
