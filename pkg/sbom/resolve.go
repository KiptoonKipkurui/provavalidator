package sbom

import (
	"context"
)

type ResolveOptions struct {
	// if true, fail when no signed SBOM is found
	RequireSigned bool
}

func ResolveForImage(ctx context.Context, imageRef string) (*ResolvedSBOM, error) {
	// Fallsback: generate SBOM on demand
	gen, err := withRuntimeEnvironment(ctx, func(runCtx context.Context, _ resolvedRuntimeConfig) (*ResolvedSBOM, error) {
		return generateSBOMForImage(runCtx, imageRef)
	})

	if err != nil {
		return nil, err
	}

	// TODO: future expansion: extract from
	return gen, nil
}
