package attestation

import "github.com/in-toto/in-toto-golang/in_toto"

type VerifiedAttestation struct {
	ImageRef string `json:"image_ref,omitempty"`

	// Who signed it.
	Subject string `json:"subject,omitempty"`
	Issuer  string `json:"issuer,omitempty"`

	// Verification evidence.
	RekorEntryPresent bool `json:"rekor_entry_present"`

	// What image digest this attestation applies to.
	ImageDigest string `json:"image_digest,omitempty"`

	// What this attestation says.
	PredicateType string `json:"predicate_type,omitempty"`
	SourceRepo    string `json:"source_repo,omitempty"`
	BuilderID     string `json:"builder_id,omitempty"`
	WorkflowRef   string `json:"workflow_ref,omitempty"`
}

type VerificationReport struct {
	ImageRef      string                `json:"image_ref"`
	Discovered    bool                  `json:"discovered"`
	Verified      bool                  `json:"verified"`
	Status        string                `json:"status"`
	Error         string                `json:"error,omitempty"`
	Attestations  []VerifiedAttestation `json:"attestations,omitempty"`
	SigningMethod string                `json:"signing_method,omitempty"`
}

type VerifiedStatement struct {
	Attestation VerifiedAttestation
	Statement   *in_toto.Statement
}
