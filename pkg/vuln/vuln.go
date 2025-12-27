package vuln

import (
	"context"
	"fmt"
)

func ScanVulnerabilities(ctx context.Context, image string) error {
	// TODO: integrate Grype or OSV queries
	fmt.Println("[vuln] Scanning vulnerabilities for:", image)
	return nil
}
