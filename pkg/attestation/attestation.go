package attestation

import (
	"context"
	"fmt"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/kiptoonkipkurui/provavalidator/pkg/registryauth"
)

// VerifiedAttestation is the minimal trusted output
type VerifiedAttestation struct {
	ImageRef string

	// Who signed it
	Subject string

	Issuer string

	// What image digest this attestation applies to
	ImageDigest string
}

// VerifyImageAttestations fetches and verifies signed attestations for an image
func VerifyImageAttestations(ctx context.Context, image string, authCfg *registryauth.Config) ([]VerifiedAttestation, error) {
	// Implementation to verify attestation for the given image

	ref, err := name.ParseReference(image)

	if err != nil {
		return nil, fmt.Errorf("parse image ref: %w", err)
	}

	atts, err := verifyWithCosign(ctx, ref, authCfg)

	if err != nil {
		return nil, err
	}

	for i := range atts {
		atts[i].ImageRef = image
	}

	if len(atts) == 0 {
		return nil, fmt.Errorf("no valid attestations found")
	}

	// TODO:
	/*
		Handle Cosign errors
		Cosign error	Status
		ErrNoMatchingAttestations	not_found
		manifest unknown	not_found
		invalid signature	invalid
		digest mismatch	invalid
		UNAUTHORIZED / DENIED	auth_error
		rekor unreachable	unavailable
		rate limit	registry_error
	*/
	return atts, nil
}
