package handler

import "github.com/glauth/glauth/v2/pkg/config"

func mapIntSliceToSet(values []int) map[int]bool {
	set := make(map[int]bool, len(values))
	for _, value := range values {
		set[value] = true
	}
	return set
}

// ExpandIncludedGroups follows IncludeGroups downward from each seed gid: it
// answers "which groups' members does this group inherit". A group inherits
// from each listed child, transitively, so the result contains the seed and
// every group reachable through its IncludeGroups chain.
//
// The walk is cycle safe: a group already visited is never expanded again, so
// cyclic or diamond-shaped inheritance cannot recurse forever or duplicate
// entries.
func ExpandIncludedGroups(groups []config.Group, seeds []int) []int {
	includes := make(map[int][]int, len(groups))
	for _, group := range groups {
		includes[group.GIDNumber] = group.IncludeGroups
	}

	visited := make(map[int]bool)
	var walk func(gid int)
	walk = func(gid int) {
		if _, known := includes[gid]; !known {
			return
		}
		if visited[gid] {
			return
		}
		visited[gid] = true
		for _, included := range includes[gid] {
			walk(included)
		}
	}
	for _, seed := range seeds {
		walk(seed)
	}

	result := make([]int, 0, len(visited))
	for gid := range visited {
		result = append(result, gid)
	}
	return result
}

// ExpandParentGroups walks IncludeGroups in the opposite direction, from a
// child group up to every parent that inherits its members. It answers
// "which groups does a membership in one of the seed groups effectively belong
// to", which is what a user's memberOf attribute must list. The seed gids are
// always part of the result.
//
// As with ExpandIncludedGroups, the traversal is cycle and diamond safe.
func ExpandParentGroups(groups []config.Group, seeds []int) []int {
	parents := make(map[int][]int, len(groups))
	for _, group := range groups {
		for _, child := range group.IncludeGroups {
			parents[child] = append(parents[child], group.GIDNumber)
		}
	}

	visited := make(map[int]bool)
	var walk func(gid int)
	walk = func(gid int) {
		if visited[gid] {
			return
		}
		visited[gid] = true
		for _, parent := range parents[gid] {
			walk(parent)
		}
	}
	for _, seed := range seeds {
		walk(seed)
	}

	result := make([]int, 0, len(visited))
	for gid := range visited {
		result = append(result, gid)
	}
	return result
}
