package handler

import (
	"fmt"
	"sort"
	"testing"

	"github.com/glauth/glauth/v2/pkg/config"
)

var diamondGroups = []config.Group{
	{Name: "engineering", GIDNumber: 5501, IncludeGroups: []int{5502, 5503}},
	{Name: "developers", GIDNumber: 5502, IncludeGroups: []int{5504}},
	{Name: "qa", GIDNumber: 5503, IncludeGroups: []int{5504}}, // 5504 reached twice
	{Name: "everyone", GIDNumber: 5504},
}

func assertInts(t *testing.T, got, want []int) {
	t.Helper()
	sort.Ints(got)
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestExpandIncludedGroups(t *testing.T) {
	// engineering inherits developers and qa, which both inherit everyone.
	got := ExpandIncludedGroups(diamondGroups, []int{5501})
	assertInts(t, got, []int{5501, 5502, 5503, 5504})
}

func TestExpandIncludedGroupsCycleSafe(t *testing.T) {
	groups := []config.Group{
		{Name: "a", GIDNumber: 5501, IncludeGroups: []int{5502}},
		{Name: "b", GIDNumber: 5502, IncludeGroups: []int{5503}},
		{Name: "c", GIDNumber: 5503, IncludeGroups: []int{5501}},
	}
	got := ExpandIncludedGroups(groups, []int{5501})
	assertInts(t, got, []int{5501, 5502, 5503})
}

func TestExpandIncludedGroupsUnknownGID(t *testing.T) {
	groups := []config.Group{
		{Name: "a", GIDNumber: 5501, IncludeGroups: []int{9999}},
	}
	got := ExpandIncludedGroups(groups, []int{5501})
	assertInts(t, got, []int{5501})
}

func TestExpandParentGroups(t *testing.T) {
	groups := []config.Group{
		{Name: "engineering", GIDNumber: 5501, IncludeGroups: []int{5502, 5503}},
		{Name: "engineers", GIDNumber: 5502},
		{Name: "qa", GIDNumber: 5503},
		{Name: "everyone", GIDNumber: 5504, IncludeGroups: []int{5501}},
	}

	// An engineers membership is visible in engineering and everyone.
	assertInts(t, ExpandParentGroups(groups, []int{5502}), []int{5501, 5502, 5504})

	// Both leaves resolve to the leaves plus both ancestors, deduplicated.
	assertInts(t, ExpandParentGroups(groups, []int{5502, 5503}), []int{5501, 5502, 5503, 5504})
}

func TestExpandParentGroupsCycleSafe(t *testing.T) {
	groups := []config.Group{
		{Name: "a", GIDNumber: 5501, IncludeGroups: []int{5502}},
		{Name: "b", GIDNumber: 5502, IncludeGroups: []int{5503}},
		{Name: "c", GIDNumber: 5503, IncludeGroups: []int{5501}},
	}
	got := ExpandParentGroups(groups, []int{5502})
	assertInts(t, got, []int{5501, 5502, 5503})
}
