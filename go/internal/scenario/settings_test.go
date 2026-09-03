package scenario

import (
	"encoding/json"
	"testing"
)

// oriole_conf holds POSTMASTER-level settings -- buffer sizes, the undo ring,
// the bgwriter -- which cannot be set per session. They are the reason some
// findings reproduce at all: a tiny main_buffers makes eviction happen at
// thousands of rows instead of millions. Recorded and parsed since the port
// began, applied by nothing, so every replay ran on the engine's much larger
// defaults and anything needing eviction pressure came back clean.
func TestPostmasterSettingsRenderJSONFaithfully(t *testing.T) {
	// Exactly as it arrives from a recorded artifact: through JSON, so every
	// number is a float64.
	var sc Scenario
	raw := `{"oriole_conf":{
		"orioledb.main_buffers":"16MB",
		"orioledb.undo_circular_buffer_size":16,
		"orioledb.debug_disable_bgwriter":true,
		"some.ratio":0.25}}`
	if err := json.Unmarshal([]byte(raw), &sc); err != nil {
		t.Fatal(err)
	}

	got := PostmasterSettings(sc)
	want := map[string]string{
		"orioledb.main_buffers":              "16MB",
		"orioledb.undo_circular_buffer_size": "16", // not "16.000000"
		"orioledb.debug_disable_bgwriter":    "on", // not "true"
		"some.ratio":                         "0.25",
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
}

func TestNoOrioleConfMeansNoSettings(t *testing.T) {
	if got := PostmasterSettings(Scenario{}); got != nil {
		t.Errorf("an ordinary scenario produced settings: %v", got)
	}
}
