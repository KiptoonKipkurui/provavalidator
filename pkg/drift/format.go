package drift

import (
	"fmt"
)

func FormatDrift(res *DriftResult) string {
	if !res.Drifted {
		return "✅ No layer drift detected"
	}

	out := "❌ Layer drift detected\n\n"

	if len(res.Changed) > 0 {
		out += "Changed layers:\n"
		for _, c := range res.Changed {
			out += fmt.Sprintf(
				"  - index %d\n    expected: %s\n    actual:   %s\n",
				c.Index, c.Expected, c.Actual,
			)
		}
		out += "\n"
	}

	if len(res.Missing) > 0 {
		out += "Missing layers:\n"
		for _, h := range res.Missing {
			out += fmt.Sprintf("  - %s\n", h)
		}
		out += "\n"
	}

	if len(res.Extra) > 0 {
		out += "Extra layers:\n"
		for _, h := range res.Extra {
			out += fmt.Sprintf("  - %s\n", h)
		}
		out += "\n"
	}

	return out
}
