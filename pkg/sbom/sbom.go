package sbom

import (
	"context"
	"fmt"

	"github.com/kiptoonkipkurui/provavalidator/pkg/attestation"
)

var extractAttestedSBOM = attestation.ExtractSBOM
var generateImageSBOM = generateSBOMForImage

func ExtractSBOM(ctx context.Context, image string) (*ResolvedSBOM, error) {
	if attested, err := resolveAttestedSBOM(ctx, image); err == nil && attested != nil {
		return attested, nil
	}

	genSbom, err := withRuntimeEnvironment(ctx, func(runCtx context.Context, _ resolvedRuntimeConfig) (*ResolvedSBOM, error) {
		return generateImageSBOM(runCtx, image)
	})
	if err != nil {
		return nil, fmt.Errorf("failed to generate SBOM: %w", err)
	}

	return genSbom, nil
}

func resolveAttestedSBOM(ctx context.Context, image string) (*ResolvedSBOM, error) {
	payload, _, err := extractAttestedSBOM(ctx, image)
	if err != nil {
		return nil, err
	}

	decoded, err := DecodeBytes(payload)
	if err != nil {
		return nil, fmt.Errorf("decode attested SBOM: %w", err)
	}

	return &ResolvedSBOM{
		Source:     SourceAttestation,
		Format:     decoded.FormatID,
		Packages:   NormalizePackage(decoded.SBOM),
		RawPayload: payload,
	}, nil
}
