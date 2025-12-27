package sbom

import (
	"sort"
	"strings"

	"github.com/anchore/syft/syft/file"
)

func normalizeLocations(ls file.LocationSet) []string {

	locs := ls.ToSlice()
	out := make([]string, 0, len(locs))
	seen := map[string]struct{}{}

	for _, loc := range locs {
		// location has a "RealPath" concept in Syft's model; String() is also useful
		// We'll prefer a stable string that matches what you'd use in policy output
		s := strings.TrimSpace(loc.RealPath)
		if s == "" {
			s = strings.TrimSpace(loc.String())
		}
		if s == "" {
			continue
		}

		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}
