package sbom

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"

	"github.com/anchore/syft/syft"
	_ "modernc.org/sqlite"
)

func generateSBOMForImage(ctx context.Context, imageRef string) (*ResolvedSBOM, error) {
	srcCfg := syft.DefaultGetSourceConfig()

	src, err := syft.GetSource(ctx, imageRef, srcCfg)
	if err != nil {
		return nil, fmt.Errorf("get source: %w", err)
	}
	defer src.Close()
	cfg := syft.DefaultCreateSBOMConfig()

	sbomResult, err := syft.CreateSBOM(ctx, src, cfg)
	if err != nil {
		return nil, fmt.Errorf("create SBOM: %w", err)
	}
	res := &ResolvedSBOM{
		Source:   SourceGenerated,
		Format:   "syft-json",
		Packages: NormalizePackage(sbomResult),
	}
	return res, nil
}

func generateSBOMForImageCLI(ctx context.Context, imageRef string) (*ResolvedSBOM, error) {
	cmd := exec.CommandContext(
		ctx,
		"syft",
		imageRef,
		"-o",
		"cyclonedx-json",
	)

	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("syft CLI failed: %w\n%s", err, out.String())
	}
	decoded, err := DecodeBytes(out.Bytes())
	if err != nil {
		return nil, fmt.Errorf("decode generated SBOM: %w", err)
	}

	return &ResolvedSBOM{
		Source:     SourceGenerated,
		Format:     decoded.FormatID,
		Packages:   NormalizePackage(decoded.SBOM),
		RawPayload: out.Bytes(),
	}, nil
}
