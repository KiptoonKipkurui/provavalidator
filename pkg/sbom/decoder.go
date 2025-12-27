package sbom

import (
	"bytes"
	"fmt"
	"io"
	"os"

	"github.com/anchore/syft/syft/format"
	syftsobm "github.com/anchore/syft/syft/sbom"
)

// DecodeResult includes the parsed SBOM plus what Syft inferred about the input
type DecodeResult struct {
	SBOM     *syftsobm.SBOM
	FormatID string // e.g "spdx-json", "cyclonedx-xml", etc.
	Info     string // decoder-specific info, sometimes empty
}

// Decode reads SBOM content in any fomrat Syft supports and returns a Syft SBOM model
// THis is the core you'll reuse for
// -Local files
//   - SBOMs pulled from registries/attestations
//
// - SBOMs embedded in CI artifacts
func Decode(r io.Reader) (*DecodeResult, error) {
	if r == nil {
		return nil, fmt.Errorf("sbom decode: reader is nil")
	}

	decoders := format.NewDecoderCollection(format.Decoders()...)

	doc, formatID, info, err := decoders.Decode(r)
	if err != nil {
		return nil, fmt.Errorf("sbom decode: unable to decode input: %w", err)
	}

	return &DecodeResult{
		SBOM:     doc,
		FormatID: string(formatID),
		Info:     info,
	}, nil
}

func DecodeBytes(data []byte) (*DecodeResult, error) {
	return Decode(bytes.NewReader(data))
}

func DecodeFile(path string) (*DecodeResult, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("sbom decode: unable to open file %q: %w", path, err)
	}
	defer f.Close()

	return Decode(f)
}
