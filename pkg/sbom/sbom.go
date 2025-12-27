package sbom

import (
	"context"
	"fmt"
)

func ExtractSBOM(ctx context.Context, image string) error {
	// TODO: integrate Syft library
	fmt.Println("[sbom] Extracting SBOM for:", image)
	return nil
}
