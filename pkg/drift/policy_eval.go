package drift

import "fmt"

func EvaluatePolicy(res *DriftResult, p Policy) error {
	if !res.Drifted {
		return nil
	}

	// Extra layers

	if len(res.Extra) > 0 && !p.AllowExtra {
		return fmt.Errorf("drift detected: extra layers found: %v", res.Extra)
	}

	// Missing layers
	if len(res.Missing) > 0 && !p.AllowMissing {
		return fmt.Errorf("drift detected: missing layers found: %v", res.Missing)
	}

	// Changed layers
	if len(res.Changed) > 0 {
		return fmt.Errorf("changed layers detected (%d)", len(res.Changed))
	}

	// Reorder detection (optional future logic)
	if !p.AllowReorder && isReordered(res) {
		return fmt.Errorf("layer order changed")
	}
	return nil
}

// placeholder if you add reorder logic later
func isReordered(res *DriftResult) bool {
	return false
}
