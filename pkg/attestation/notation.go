package attestation

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/kiptoonkipkurui/provavalidator/pkg/registryauth"
	_ "github.com/notaryproject/notation-core-go/signature/cose"
	_ "github.com/notaryproject/notation-core-go/signature/jws"
	notation "github.com/notaryproject/notation-go"
	"github.com/notaryproject/notation-go/dir"
	notationregistry "github.com/notaryproject/notation-go/registry"
	notationverifier "github.com/notaryproject/notation-go/verifier"
	notationtrustpolicy "github.com/notaryproject/notation-go/verifier/trustpolicy"
	notationtruststore "github.com/notaryproject/notation-go/verifier/truststore"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	orasremote "oras.land/oras-go/v2/registry/remote"
	orasauth "oras.land/oras-go/v2/registry/remote/auth"
)

func inspectWithNotation(ctx context.Context, image string, authCfg *registryauth.Config) (*VerificationReport, error) {
	discovered, targetDesc, err := discoverWithNotation(ctx, image, authCfg)
	if err != nil {
		classified := classifyNotationError(err)
		return &VerificationReport{
			ImageRef:      image,
			Status:        verificationStatus(classified),
			Error:         classified.Error(),
			SigningMethod: "notation",
		}, classified
	}
	if len(discovered) == 0 {
		err := &VerificationError{
			Status: "not_found",
			Err:    fmt.Errorf("no notation signatures found"),
		}
		return &VerificationReport{
			ImageRef:      image,
			Status:        "not_found",
			Error:         err.Error(),
			SigningMethod: "notation",
		}, err
	}

	verified, err := verifyWithNotation(ctx, image, authCfg)
	if err != nil {
		classified := classifyNotationError(err)
		return &VerificationReport{
			ImageRef:      image,
			Discovered:    true,
			Verified:      false,
			Status:        verificationStatus(classified),
			Error:         classified.Error(),
			Attestations:  mergeNotationDetails(discovered, targetDesc),
			SigningMethod: "notation",
		}, classified
	}

	return &VerificationReport{
		ImageRef:      image,
		Discovered:    true,
		Verified:      true,
		Status:        "verified",
		Attestations:  verified,
		SigningMethod: "notation",
	}, nil
}

func discoverWithNotation(ctx context.Context, image string, authCfg *registryauth.Config) ([]VerifiedAttestation, ocispec.Descriptor, error) {
	repo, err := newNotationRepository(image, authCfg)
	if err != nil {
		return nil, ocispec.Descriptor{}, err
	}

	targetDesc, sigs, err := listNotationSignatures(ctx, repo, image)
	if err != nil {
		return nil, ocispec.Descriptor{}, err
	}
	if len(sigs) == 0 {
		return nil, targetDesc, nil
	}

	return mergeNotationDetails(notationDescriptorsToAttestations(image, targetDesc, sigs), targetDesc), targetDesc, nil
}

func verifyWithNotation(ctx context.Context, image string, authCfg *registryauth.Config) ([]VerifiedAttestation, error) {
	repo, err := newNotationRepository(image, authCfg)
	if err != nil {
		return nil, err
	}

	v, err := newNotationVerifier(authCfg)
	if err != nil {
		return nil, err
	}

	targetDesc, outcomes, err := notation.Verify(ctx, v, repo, notation.VerifyOptions{
		ArtifactReference:    image,
		MaxSignatureAttempts: 50,
	})
	if err != nil {
		return nil, err
	}
	if len(outcomes) == 0 {
		return nil, fmt.Errorf("notation verification returned no outcomes")
	}

	results := make([]VerifiedAttestation, 0, len(outcomes))
	for _, outcome := range outcomes {
		if outcome == nil || outcome.EnvelopeContent == nil {
			continue
		}

		subject, issuer := notationCertSubjectIssuer(outcome.EnvelopeContent.SignerInfo.CertificateChain)
		results = append(results, VerifiedAttestation{
			ImageRef:          image,
			Subject:           subject,
			Issuer:            issuer,
			RekorEntryPresent: false,
			ImageDigest:       targetDesc.Digest.String(),
			PredicateType:     "notation-signature",
			SourceRepo:        "",
			BuilderID:         "",
			WorkflowRef:       "",
		})
	}

	if len(results) == 0 {
		return nil, fmt.Errorf("notation verification succeeded without a usable signer outcome")
	}

	return results, nil
}

func newNotationVerifier(authCfg *registryauth.Config) (notation.Verifier, error) {
	if authCfg == nil || notationUsesDefaultConfig(authCfg.Notation) {
		return notationverifier.NewFromConfig()
	}

	policyDoc, err := loadNotationPolicy(authCfg.Notation)
	if err != nil {
		return nil, err
	}

	trustStoreRoot, err := notationTrustStoreRoot(authCfg.Notation)
	if err != nil {
		return nil, err
	}

	return notationverifier.New(
		policyDoc,
		notationtruststore.NewX509TrustStore(dir.NewSysFS(trustStoreRoot)),
		nil,
	)
}

func newNotationRepository(image string, authCfg *registryauth.Config) (notationregistry.Repository, error) {
	repo, err := orasremote.NewRepository(image)
	if err != nil {
		return nil, fmt.Errorf("notation repository: %w", err)
	}

	repo.Client = &orasauth.Client{
		Credential: notationCredentialFunc(authCfg),
		Cache:      orasauth.NewCache(),
	}

	return notationregistry.NewRepository(repo), nil
}

func listNotationSignatures(ctx context.Context, repo notationregistry.Repository, image string) (ocispec.Descriptor, []ocispec.Descriptor, error) {
	remoteRepo, err := orasremote.NewRepository(image)
	if err != nil {
		return ocispec.Descriptor{}, nil, fmt.Errorf("parse notation reference: %w", err)
	}

	ref := remoteRepo.Reference.Reference
	if ref == "" {
		return ocispec.Descriptor{}, nil, fmt.Errorf("notation reference is missing digest or tag")
	}

	targetDesc, err := repo.Resolve(ctx, ref)
	if err != nil {
		return ocispec.Descriptor{}, nil, fmt.Errorf("discover notation signatures: %w", err)
	}

	var sigs []ocispec.Descriptor
	if err := repo.ListSignatures(ctx, targetDesc, func(signatureManifests []ocispec.Descriptor) error {
		sigs = append(sigs, signatureManifests...)
		return nil
	}); err != nil {
		return ocispec.Descriptor{}, nil, fmt.Errorf("discover notation signatures: %w", err)
	}

	return targetDesc, sigs, nil
}

func notationCredentialFunc(cfg *registryauth.Config) orasauth.CredentialFunc {
	return func(ctx context.Context, hostport string) (orasauth.Credential, error) {
		keychain := registryauth.NewOverrideKeychain(cfg, authn.DefaultKeychain)
		authenticator, err := keychain.Resolve(registryResource(hostport))
		if err != nil {
			return orasauth.EmptyCredential, err
		}

		authCfg, err := authn.Authorization(ctx, authenticator)
		if err != nil {
			return orasauth.EmptyCredential, err
		}
		if authCfg == nil {
			return orasauth.EmptyCredential, nil
		}

		switch {
		case authCfg.RegistryToken != "":
			return orasauth.Credential{AccessToken: authCfg.RegistryToken}, nil
		case authCfg.IdentityToken != "":
			return orasauth.Credential{RefreshToken: authCfg.IdentityToken}, nil
		case authCfg.Username != "" || authCfg.Password != "":
			return orasauth.Credential{
				Username: authCfg.Username,
				Password: authCfg.Password,
			}, nil
		default:
			return orasauth.EmptyCredential, nil
		}
	}
}

type registryResource string

func (r registryResource) String() string {
	return string(r)
}

func (r registryResource) RegistryStr() string {
	return string(r)
}

func notationDescriptorsToAttestations(image string, targetDesc ocispec.Descriptor, sigs []ocispec.Descriptor) []VerifiedAttestation {
	results := make([]VerifiedAttestation, 0, len(sigs))
	for range sigs {
		results = append(results, VerifiedAttestation{
			ImageRef:      image,
			ImageDigest:   targetDesc.Digest.String(),
			PredicateType: "notation-signature",
			Subject:       "notation-signature",
		})
	}
	return results
}

func notationUsesDefaultConfig(cfg registryauth.NotationConfig) bool {
	return cfg.ConfigDir == "" && cfg.TrustPolicyPath == "" && cfg.TrustStorePath == ""
}

func loadNotationPolicy(cfg registryauth.NotationConfig) (*notationtrustpolicy.Document, error) {
	path := cfg.TrustPolicyPath
	if path == "" && cfg.ConfigDir != "" {
		path = filepath.Join(cfg.ConfigDir, dir.PathTrustPolicy)
	}
	if path == "" {
		return nil, fmt.Errorf("notation trust policy path is not configured")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read notation trust policy: %w", err)
	}

	var doc notationtrustpolicy.Document
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse notation trust policy: %w", err)
	}
	if err := doc.Validate(); err != nil {
		return nil, fmt.Errorf("validate notation trust policy: %w", err)
	}

	return &doc, nil
}

func notationTrustStoreRoot(cfg registryauth.NotationConfig) (string, error) {
	path := cfg.TrustStorePath
	if path == "" && cfg.ConfigDir != "" {
		return cfg.ConfigDir, nil
	}
	if path == "" {
		return "", fmt.Errorf("notation trust store path is not configured")
	}

	info, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("stat notation trust store path: %w", err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("notation trust store path %q is not a directory", path)
	}

	clean := filepath.Clean(path)
	if filepath.Base(clean) == dir.TrustStoreDir {
		return filepath.Dir(clean), nil
	}
	if _, err := os.Stat(filepath.Join(clean, dir.TrustStoreDir)); err == nil {
		return clean, nil
	}
	if _, err := os.Stat(filepath.Join(clean, "x509")); err == nil {
		return filepath.Dir(clean), nil
	}

	return clean, nil
}

func mergeNotationDetails(atts []VerifiedAttestation, targetDesc ocispec.Descriptor) []VerifiedAttestation {
	for i := range atts {
		if atts[i].ImageDigest == "" {
			atts[i].ImageDigest = targetDesc.Digest.String()
		}
		if atts[i].PredicateType == "" {
			atts[i].PredicateType = "notation-signature"
		}
	}
	return atts
}

func notationCertSubjectIssuer(chain []*x509.Certificate) (string, string) {
	if len(chain) == 0 || chain[0] == nil {
		return "", ""
	}
	return chain[0].Subject.String(), chain[0].Issuer.String()
}

func classifyNotationError(err error) error {
	status := "invalid"
	msg := strings.ToLower(err.Error())

	var retrievalErr notation.SignatureRetrievalFailedError
	var verificationErr notation.VerificationFailedError
	var inconclusiveErr notation.VerificationInconclusiveError
	var trustPolicyErr notation.NoApplicableTrustPolicyError

	switch {
	case errors.As(err, &trustPolicyErr):
		status = "verification_incompatible"
	case errors.As(err, &inconclusiveErr):
		status = "unavailable"
	case errors.As(err, &retrievalErr):
		status = "not_found"
	case errors.As(err, &verificationErr):
		status = "invalid"
	}

	switch {
	case strings.Contains(msg, "no signature is associated"),
		strings.Contains(msg, "no notation signatures found"),
		strings.Contains(msg, "manifest unknown"),
		strings.Contains(msg, "404"):
		status = "not_found"
	case strings.Contains(msg, "requested access to the resource is denied"),
		strings.Contains(msg, "authentication required"),
		strings.Contains(msg, "insufficient_scope"):
		status = "auth_required"
	case strings.Contains(msg, "unauthorized"),
		strings.Contains(msg, "denied"):
		status = "auth_error"
	case strings.Contains(msg, "trust policy"),
		strings.Contains(msg, "trust store"),
		strings.Contains(msg, "certificate chain"),
		strings.Contains(msg, "signing scheme"),
		strings.Contains(msg, "plugin"):
		status = "verification_incompatible"
	case strings.Contains(msg, "signature verification failed"),
		strings.Contains(msg, "content descriptor mismatch"),
		strings.Contains(msg, "integrity"),
		strings.Contains(msg, "expiry"),
		strings.Contains(msg, "revocation"):
		status = "invalid"
	case strings.Contains(msg, "rate limit"),
		strings.Contains(msg, "too many requests"),
		strings.Contains(msg, "toomanyrequests"):
		status = "registry_error"
	case strings.Contains(msg, "timeout"),
		strings.Contains(msg, "temporary failure"),
		strings.Contains(msg, "connection refused"),
		strings.Contains(msg, "no such host"),
		strings.Contains(msg, "unreachable"):
		status = "unavailable"
	}

	return &VerificationError{
		Status: status,
		Err:    err,
	}
}
