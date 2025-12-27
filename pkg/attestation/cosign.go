package attestation

import (
	"context"
	"crypto/x509"
	"fmt"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/kiptoonkipkurui/provavalidator/pkg/registryauth"
	"github.com/sigstore/cosign/cmd/cosign/cli/fulcio"
	cosign "github.com/sigstore/cosign/pkg/cosign"
	ociremote "github.com/sigstore/cosign/pkg/oci/remote"
)

// verifyWithCosign verifies attestations attached to an image reference
func verifyWithCosign(ctx context.Context, ref name.Reference, cfg *registryauth.Config) ([]VerifiedAttestation, error) {
	// resolve registry authentication
	keychain, _, err := registryauth.KeyChainForImage(cfg, ref.Name())

	// Optional but VERY useful for debugging
	repo := ref.Context()
	auth, _ := keychain.Resolve(repo)

	fmt.Printf("Using registry auth for %s: %T\n",
		ref.Context().RegistryStr(), auth)
	// Load Fulcio roots

	if err != nil {
		return nil, fmt.Errorf("image keychain error : %w", err)
	}

	// Load Fulcio root certificates (this is what cosign CLI does implicitly)
	roots, err := fulcio.GetRoots()
	if err != nil {
		return nil, fmt.Errorf("load fulcio roots: %w", err)
	}
	opts := &cosign.CheckOpts{
		RootCerts: roots,
		// Rekor + SCT verification are enabled by default
		// Use Docker / GHCR credentials from ~/.docker/config.json
		RegistryClientOpts: []ociremote.Option{
			ociremote.WithRemoteOptions(
				remote.WithAuthFromKeychain(authn.DefaultKeychain),
			),
		},
	}

	checked, _, err := cosign.VerifyImageAttestations(ctx, ref, opts)

	if err != nil {
		return nil, fmt.Errorf("verify attestations: %w", err)
	}
	if len(checked) == 0 {
		return nil, fmt.Errorf("no verified attestations found")
	}
	var results = make([]VerifiedAttestation, 0, len(checked))

	for _, sig := range checked {

		cert, _ := sig.Cert() //cert may be nil for some verification modes

		subject, issuer := certSubjectIssuer(cert)
		results = append(results, VerifiedAttestation{
			Subject: subject,
			Issuer:  issuer,
			// ImageDigest: filled in later when we bind to the image digest
		})
	}
	return results, nil
}

func certSubjectIssuer(cert *x509.Certificate) (subject, issuer string) {
	if cert == nil {
		return "", ""
	}

	return cert.Subject.String(), cert.Issuer.String()
}
