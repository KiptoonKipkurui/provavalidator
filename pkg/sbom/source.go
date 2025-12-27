package sbom

type SourceType string

const (
	SourceAttestation SourceType = "attestation"
	SourceGenerated   SourceType = "generated"
)

type ResolvedSBOM struct {
	Source     SourceType
	Format     string
	Packages   []NormalizedPackage
	RawPayload []byte // optional; useful for debugging or export
}
