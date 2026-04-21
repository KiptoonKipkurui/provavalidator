package sbom

import (
	"context"
)

type ResolveOptions struct {
	// if true, fail when no signed SBOM is found
	RequireSigned bool
}

func ResolveForImage(ctx context.Context, imageRef string) (*ResolvedSBOM, error) {
	return ExtractSBOM(ctx, imageRef)
}
