// Package scenario is the storage_fuzzer scenario model: what a recorded
// finding actually is.
//
// A storage finding is not an input. It is a database put into a state one
// statement cannot reach -- tables across tablespaces, partitions, concurrent
// DDL, a deliberate crash and recovery -- and then checked for consistency.
// The 1,264-line Python generator that produces these is being ported here.
//
// THE MODEL IS DERIVED FROM THE RECORDED SCENARIOS, NOT FROM THE GENERATOR.
// 27 distinct (scenario, setup-SQL) pairs survive in FINDINGS, carrying 9
// scenario keys, 14 table keys, 9 index kinds and 31 step operations between
// them. Those files are the specification: they are what the findings mean,
// and any port that cannot read them has not preserved the evidence.
//
// UnmarshalStrict refuses unknown fields on purpose. A key this model does not
// know is a part of a scenario that would be silently dropped -- and a
// reproduction missing a step is not a reproduction, it is a different
// experiment with the same file name.
package scenario

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// Record is a findings .json: the scenario, plus what it did.
type Record struct {
	Seed     int      `json:"seed"`
	Failure  string   `json:"failure"`
	Notes    []string `json:"notes"`
	Build    *Build   `json:"build,omitempty"`
	Scenario Scenario `json:"scenario"`
}

// Build is the provenance stamp newer records carry.
type Build struct {
	Note string `json:"note"`
}

// Scenario is the experiment itself.
type Scenario struct {
	Seed                  int            `json:"seed"`
	OrioleDB              bool           `json:"orioledb"`
	OrioleSettings        map[string]any `json:"oriole_settings,omitempty"`
	OrioleConf            map[string]any `json:"oriole_conf,omitempty"`
	WarmDefaultTablespace bool           `json:"warm_default_tablespace"`
	DefaultTablespace     *string        `json:"default_tablespace"`
	Writers               int            `json:"writers"`
	Tables                []Table        `json:"tables"`
	Steps                 []Step         `json:"steps"`
}

// Table is one relation the scenario builds.
//
// PK and PKExtra are KINDS, not column lists -- "single", "composite" -- and
// the columns follow from them. Modelling them as []string parsed nothing and
// was caught by the first test run, which is the whole reason the corpus is
// the specification rather than the generator source.
type Table struct {
	Name            string   `json:"name"`
	AM              string   `json:"am"` // orioledb | heap
	Partitioned     bool     `json:"partitioned"`
	PK              string   `json:"pk"`
	PKExtra         string   `json:"pk_extra,omitempty"`
	Unlogged        bool     `json:"unlogged"`
	Wide            bool     `json:"wide"`
	Generated       bool     `json:"generated"`
	ExtraTypes      []string `json:"extra_types"`
	Indexes         []string `json:"indexes"` // kind names: brin, gin, partial, ...
	Tablespace      *string  `json:"tablespace"`
	IndexTablespace *string  `json:"index_tablespace"`
	Rows            int      `json:"rows"`
	Compress        *int     `json:"compress,omitempty"`
}

// Step is one perturbation applied after setup. Op and the table it acts on
// are the whole of it: the recorded corpus carries no arguments.
type Step struct {
	Op    string `json:"op"`
	Table string `json:"table,omitempty"`
}

// Ops is every step operation the recorded scenarios use. A port that does not
// implement one of these cannot replay the finding that needs it, so the list
// is here rather than scattered through a switch.
var Ops = []string{
	"add_column", "alter_type", "analyze", "attach_partition", "checkpoint",
	"churn_evict", "concurrent_checkpoint", "concurrent_ddl", "concurrent_write",
	"delete_half", "detach_partition", "drop_column", "insert_more",
	"move_across_partition", "move_index", "prepare_2pc", "reindex",
	"repeatable_read_write", "restart_clean", "restart_crash", "rollback_ddl",
	"rollback_delete", "rollback_insert", "savepoint_partial",
	"serializable_write", "set_tablespace", "truncate_refill", "update_all",
	"upsert", "vacuum", "vacuum_full",
}

// UnmarshalStrict parses a findings .json and rejects anything this model does
// not know about -- see the package comment for why that is the point.
func UnmarshalStrict(b []byte) (Record, error) {
	var r Record
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(&r); err != nil {
		return Record{}, fmt.Errorf("scenario: %w", err)
	}
	return r, nil
}

// KnownOp reports whether this step is one the model claims to handle.
func KnownOp(op string) bool {
	for _, o := range Ops {
		if o == op {
			return true
		}
	}
	return false
}
