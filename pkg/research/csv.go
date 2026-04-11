package research

import (
	"encoding/csv"
	"io"
	"strconv"
	"strings"
)

func WriteCSV(w io.Writer, result *CorpusResult) error {
	writer := csv.NewWriter(w)

	header := []string{
		"image",
		"registry",
		"repository",
		"publisher",
		"digest",
		"digest_ref",
		"provenance_verified",
		"provenance_status",
		"provenance_error",
		"signing_method",
		"attestation_count",
		"rekor_entry_present",
		"predicate_types",
		"subject_identities",
		"issuers",
		"source_repo",
		"source_repo_linked",
		"builder_id",
		"workflow_ref",
		"resolve_ms",
		"attestation_ms",
		"sbom_ms",
		"vulnerability_ms",
		"total_ms",
		"sbom_available",
		"sbom_source",
		"sbom_format",
		"package_count",
		"vulnerability_scan",
		"vulnerability_error",
		"vulnerability_total",
		"critical_count",
		"high_count",
		"medium_count",
		"low_count",
		"unknown_count",
		"score",
		"notes",
	}

	if err := writer.Write(header); err != nil {
		return err
	}

	for _, image := range result.Images {
		row := []string{
			image.ImageRef,
			image.Registry,
			image.Repository,
			image.Publisher,
			image.ResolvedDigest,
			image.DigestRef,
			strconv.FormatBool(image.ProvenanceVerified),
			image.ProvenanceStatus,
			image.ProvenanceError,
			image.SigningMethod,
			strconv.Itoa(image.AttestationCount),
			strconv.FormatBool(image.RekorEntryPresent),
			strings.Join(image.PredicateTypes, ";"),
			strings.Join(image.SubjectIdentities, ";"),
			strings.Join(image.Issuers, ";"),
			image.SourceRepo,
			strconv.FormatBool(image.SourceRepoLinked),
			image.BuilderID,
			image.WorkflowRef,
			strconv.FormatInt(image.ResolveMillis, 10),
			strconv.FormatInt(image.AttestationMillis, 10),
			strconv.FormatInt(image.SBOMMillis, 10),
			strconv.FormatInt(image.VulnerabilityMillis, 10),
			strconv.FormatInt(image.TotalMillis, 10),
			strconv.FormatBool(image.SBOMAvailable),
			image.SBOMSource,
			image.SBOMFormat,
			strconv.Itoa(image.PackageCount),
			image.VulnerabilityScan,
			image.VulnerabilityError,
			strconv.Itoa(image.VulnerabilityTotal),
			strconv.Itoa(image.CriticalCount),
			strconv.Itoa(image.HighCount),
			strconv.Itoa(image.MediumCount),
			strconv.Itoa(image.LowCount),
			strconv.Itoa(image.UnknownCount),
			strconv.Itoa(image.Score),
			strings.Join(image.Notes, ";"),
		}
		if err := writer.Write(row); err != nil {
			return err
		}
	}

	writer.Flush()
	return writer.Error()
}
