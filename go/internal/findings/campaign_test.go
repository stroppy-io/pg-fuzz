package findings

import "testing"

// UNAMBIGUOUS ONLY.
//
// A write-up is attributed when the workspaces it names resolve, through the
// manifests, to exactly one campaign. Several campaigns is not an attribution
// -- the finding was seen in more than one place and picking one invents the
// answer -- and none is not either.
func TestCampaignForRequiresOneAnswer(t *testing.T) {
	byWS := map[string][]string{
		"a-add": {"camp-1"},
		"b-add": {"camp-1"},
		"c-add": {"camp-2"},
	}
	if got, ok := CampaignFor([]string{"a-add", "b-add"}, byWS); !ok || got != "camp-1" {
		t.Errorf("got %q ok=%v, want camp-1 -- both workspaces are its own", got, ok)
	}
	if _, ok := CampaignFor([]string{"a-add", "c-add"}, byWS); ok {
		t.Error("two campaigns produced an attribution; one of them would be invented")
	}
	if _, ok := CampaignFor([]string{"unknown-add"}, byWS); ok {
		t.Error("a workspace no manifest records produced an attribution")
	}
	if _, ok := CampaignFor(nil, byWS); ok {
		t.Error("naming no workspace produced an attribution")
	}
}

// "unknown" is an ANSWER; an absent field is a question never asked. The gate
// has to tell them apart.
func TestMissingCampaignIsNotUnknown(t *testing.T) {
	if Campaign("# t\n\n**Campaign:** unknown\n") != "unknown" {
		t.Error("a recorded unknown did not parse")
	}
	if Campaign("# t\n\n**Status:** open\n") != "" {
		t.Error("an absent field parsed as something")
	}
}
