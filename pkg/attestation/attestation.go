package attestation

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/kiptoonkipkurui/provavalidator/pkg/registryauth"
	cosign "github.com/sigstore/cosign/pkg/cosign"
)

type VerificationError struct {
	Status string
	Err    error
}

func (e *VerificationError) Error() string {
	return e.Err.Error()
}

func (e *VerificationError) Unwrap() error {
	return e.Err
}

func (e *VerificationError) StatusCode() string {
	return e.Status
}

func InspectImageAttestations(ctx context.Context, image string, authCfg *registryauth.Config) (*VerificationReport, error) {
	ref, err := name.ParseReference(image)
	if err != nil {
		return &VerificationReport{
			ImageRef: image,
			Status:   "invalid_reference",
			Error:    err.Error(),
		}, fmt.Errorf("parse image ref: %w", err)
	}

	atts, err := verifyWithCosign(ctx, ref, authCfg)
	if err != nil {
		classified := classifyVerificationError(err)
		if shouldTryNotationFallback(classified) {
			notationReport, notationErr := inspectWithNotation(ctx, image, authCfg)
			if notationReport != nil {
				notationStatus := verificationStatus(notationErr)
				if notationReport.Verified || notationReport.Discovered {
					return notationReport, notationErr
				}
				if verificationStatus(classified) == "not_found" && notationStatus != "not_found" {
					return notationReport, notationErr
				}
			}
		}
		discovered, discoverErr := discoverWithCosign(ctx, ref, authCfg)
		report := &VerificationReport{
			ImageRef:      image,
			Status:        verificationStatus(classified),
			Error:         classified.Error(),
			Attestations:  discovered,
			Discovered:    len(discovered) > 0,
			SigningMethod: signingMethod(discovered),
		}
		if discoverErr == nil && len(discovered) > 0 && report.Status == "not_found" {
			report.Status = "verification_incompatible"
		}
		return report, classified
	}

	for i := range atts {
		atts[i].ImageRef = image
	}

	report := &VerificationReport{
		ImageRef:      image,
		Discovered:    len(atts) > 0,
		Verified:      len(atts) > 0,
		Status:        "verified",
		Attestations:  atts,
		SigningMethod: signingMethod(atts),
	}

	if len(atts) == 0 {
		report.Status = "not_found"
		report.Verified = false
		report.Error = "no valid attestations found"
		return report, &VerificationError{
			Status: "not_found",
			Err:    fmt.Errorf("no valid attestations found"),
		}
	}

	return report, nil
}

func shouldTryNotationFallback(err error) bool {
	switch verificationStatus(err) {
	case "not_found", "verification_incompatible", "invalid", "unavailable":
		return true
	default:
		return false
	}
}

// VerifyImageAttestations fetches and verifies signed attestations for an image
func VerifyImageAttestations(ctx context.Context, image string, authCfg *registryauth.Config) ([]VerifiedAttestation, error) {
	report, err := InspectImageAttestations(ctx, image, authCfg)
	if err != nil {
		return nil, err
	}

	return report.Attestations, nil
}

func classifyVerificationError(err error) error {
	status := "invalid"

	switch {
	case errors.Is(err, cosign.ErrNoMatchingAttestations):
		status = "not_found"
	default:
		msg := strings.ToLower(err.Error())

		switch {
		case strings.Contains(msg, "manifest unknown"):
			status = "not_found"
		case strings.Contains(msg, "requested access to the resource is denied"),
			strings.Contains(msg, "authentication required"),
			strings.Contains(msg, "insufficient_scope"):
			status = "auth_required"
		case strings.Contains(msg, "invalid signature"),
			strings.Contains(msg, "digest mismatch"):
			status = "invalid"
		case strings.Contains(msg, "invalid kind value"),
			strings.Contains(msg, "dsse"):
			status = "verification_incompatible"
		case strings.Contains(msg, "unauthorized"),
			strings.Contains(msg, "denied"):
			status = "auth_error"
		case strings.Contains(msg, "rekor"),
			strings.Contains(msg, "timeout"),
			strings.Contains(msg, "temporary failure"),
			strings.Contains(msg, "connection refused"),
			strings.Contains(msg, "no such host"),
			strings.Contains(msg, "unreachable"):
			status = "unavailable"
		case strings.Contains(msg, "rate limit"),
			strings.Contains(msg, "too many requests"),
			strings.Contains(msg, "toomanyrequests"):
			status = "registry_error"
		}
	}

	return &VerificationError{
		Status: status,
		Err:    err,
	}
}

func verificationStatus(err error) string {
	var verr *VerificationError
	if errors.As(err, &verr) {
		return verr.Status
	}

	return "invalid"
}

func signingMethod(atts []VerifiedAttestation) string {
	for _, att := range atts {
		if att.Subject != "" || att.Issuer != "" {
			return "keyless"
		}
	}

	if len(atts) > 0 {
		return "key"
	}

	return "not_verifiable"
}
