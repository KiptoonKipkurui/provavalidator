package attestation

import "context"

// Verifier is the minimum interface sbom.ResoveForImage depends on
// THis keeps pkg/sbom decoupled from cosign internals
type Verifier interface {
	// ExtractSBOM extracts the SBOM bytes and format from a signed attestation for the given image reference
	ExtractSBOM(ctx context.Context, imageRef string) (sbomBytes []byte, format string, err error)
}

type CosignVerifier struct{}

var _ Verifier = (*CosignVerifier)(nil)

func (v *CosignVerifier) ExtractSBOM(ctx context.Context, imageRef string) (sbomBytes []byte, format string, err error) {

	// TODO: implement using cosign attestation verification
	return nil, "", nil
}
