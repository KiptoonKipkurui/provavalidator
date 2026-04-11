package sbom

import (
	"context"
	"fmt"
)

func ExtractSBOM(ctx context.Context, image string) (*ResolvedSBOM, error) {
	genSbom, err := withRuntimeEnvironment(ctx, func(runCtx context.Context, _ resolvedRuntimeConfig) (*ResolvedSBOM, error) {
		return generateSBOMForImage(runCtx, image)
	})

	if err != nil {
		return nil, fmt.Errorf("failed to generate SBOM: %w", err)
	}

	return genSbom, nil
}
