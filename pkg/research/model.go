package research

type ImageResult struct {
	ImageRef            string   `json:"image"`
	Registry            string   `json:"registry,omitempty"`
	Repository          string   `json:"repository,omitempty"`
	Publisher           string   `json:"publisher,omitempty"`
	ResolvedDigest      string   `json:"digest,omitempty"`
	DigestRef           string   `json:"digest_ref,omitempty"`
	ProvenanceVerified  bool     `json:"provenance_verified"`
	ProvenanceStatus    string   `json:"provenance_status"`
	ProvenanceError     string   `json:"provenance_error,omitempty"`
	SigningMethod       string   `json:"signing_method,omitempty"`
	AttestationCount    int      `json:"attestation_count"`
	RekorEntryPresent   bool     `json:"rekor_entry_present"`
	PredicateTypes      []string `json:"predicate_types,omitempty"`
	SubjectIdentities   []string `json:"subject_identities,omitempty"`
	Issuers             []string `json:"issuers,omitempty"`
	SourceRepo          string   `json:"source_repo,omitempty"`
	SourceRepoLinked    bool     `json:"source_repo_linked"`
	BuilderID           string   `json:"builder_id,omitempty"`
	WorkflowRef         string   `json:"workflow_ref,omitempty"`
	ResolveMillis       int64    `json:"resolve_ms"`
	AttestationMillis   int64    `json:"attestation_ms"`
	SBOMMillis          int64    `json:"sbom_ms"`
	VulnerabilityMillis int64    `json:"vulnerability_ms"`
	TotalMillis         int64    `json:"total_ms"`
	SBOMAvailable       bool     `json:"sbom_available"`
	SBOMSource          string   `json:"sbom_source,omitempty"`
	SBOMFormat          string   `json:"sbom_format,omitempty"`
	PackageCount        int      `json:"package_count"`
	VulnerabilityScan   string   `json:"vulnerability_scan"`
	VulnerabilityError  string   `json:"vulnerability_error,omitempty"`
	VulnerabilityTotal  int      `json:"vulnerability_total"`
	CriticalCount       int      `json:"critical_count"`
	HighCount           int      `json:"high_count"`
	MediumCount         int      `json:"medium_count"`
	LowCount            int      `json:"low_count"`
	UnknownCount        int      `json:"unknown_count"`
	Score               int      `json:"score"`
	Notes               []string `json:"notes,omitempty"`
}

type Summary struct {
	Total                 int `json:"total"`
	Verified              int `json:"verified"`
	WithRekor             int `json:"with_rekor"`
	WithSourceRepo        int `json:"with_source_repo"`
	WithBuilderID         int `json:"with_builder_id"`
	WithProvenanceSignal  int `json:"with_provenance_signal"`
	WithSBOM              int `json:"with_sbom"`
	WithVulnerabilityScan int `json:"with_vulnerability_scan"`
	ImagesWithCritical    int `json:"images_with_critical"`
	TotalVulnerabilities  int `json:"total_vulnerabilities"`
}

type CorpusResult struct {
	Images  []ImageResult `json:"images"`
	Summary Summary       `json:"summary"`
}
