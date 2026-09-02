package fuzz

import "testing"

// A slice reports what IT produced. The artifacts directory accumulates across
// every campaign the workspace has ever run, so reporting its total after a
// fifteen-second slice turns weeks of history into "this run found 22
// crashes" -- the artifact-versus-finding confusion the reports spend a
// section correcting, arriving through the dashboard instead.
func TestNewArtifactsIsTheSlicesOwn(t *testing.T) {
	r := Result{ArtifactsFrom: 22, ArtifactsTo: 25}
	if got := r.NewArtifacts(); got != 3 {
		t.Errorf("want 3 new, got %d", got)
	}
	// A slice that found nothing, in a directory holding weeks of finds.
	r = Result{ArtifactsFrom: 22, ArtifactsTo: 22}
	if got := r.NewArtifacts(); got != 0 {
		t.Errorf("a slice that found nothing must report 0, got %d", got)
	}
	// Artifacts removed under it -- by a triage pass, by hand -- must not
	// read as a negative discovery.
	r = Result{ArtifactsFrom: 22, ArtifactsTo: 5}
	if got := r.NewArtifacts(); got != 0 {
		t.Errorf("a shrinking directory must not report negative, got %d", got)
	}
}
