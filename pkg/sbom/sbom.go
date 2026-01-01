package sbom

import (
	"context"
	"fmt"
)

func ExtractSBOM(ctx context.Context, image string) (*ResolvedSBOM, error) {
	fmt.Println("[sbom] Extracting SBOM for:", image)

	genSbom, err := generateSBOMForImage(ctx, image)

	if err != nil {
		return nil, fmt.Errorf("failed to generate SBOM: %w", err)
	}

	fmt.Printf("Generated SBOM for image %s: %+v\n", image, genSbom)

	return genSbom, nil
}
