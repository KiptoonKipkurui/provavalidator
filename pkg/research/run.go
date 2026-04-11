package research

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/kiptoonkipkurui/provavalidator/pkg/attestation"
	"github.com/kiptoonkipkurui/provavalidator/pkg/registry"
	"github.com/kiptoonkipkurui/provavalidator/pkg/registryauth"
	"github.com/kiptoonkipkurui/provavalidator/pkg/sbom"
	"github.com/kiptoonkipkurui/provavalidator/pkg/vuln"
)

type Options struct {
	Images       []string
	AuthCfg      *registryauth.Config
	Concurrency  int
	ImageTimeout time.Duration
}

func Run(ctx context.Context, opts Options) (*CorpusResult, error) {
	if opts.Concurrency <= 0 {
		opts.Concurrency = 1
	}
	if opts.ImageTimeout <= 0 {
		opts.ImageTimeout = 90 * time.Second
	}

	type job struct {
		index int
		image string
	}

	results := make([]ImageResult, len(opts.Images))
	jobs := make(chan job)

	var wg sync.WaitGroup
	workerCount := opts.Concurrency
	if workerCount > len(opts.Images) {
		workerCount = len(opts.Images)
	}

	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
				}
				jobCtx := ctx
				cancel := func() {}
				if timeout := opts.ImageTimeout; timeout > 0 {
					jobCtx, cancel = context.WithTimeout(ctx, timeout)
				}
				results[job.index] = inspectImage(jobCtx, job.image, opts.AuthCfg)
				cancel()
			}
		}()
	}

	for i, image := range opts.Images {
		select {
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			return nil, ctx.Err()
		case jobs <- job{index: i, image: image}:
		}
	}
	close(jobs)
	wg.Wait()

	return &CorpusResult{
		Images:  results,
		Summary: summarize(results),
	}, nil
}

func inspectImage(ctx context.Context, image string, authCfg *registryauth.Config) (result ImageResult) {
	startedAt := time.Now()
	result = ImageResult{
		ImageRef:          image,
		ProvenanceStatus:  "unknown",
		VulnerabilityScan: "not_run",
	}
	defer func() {
		result.TotalMillis = durationMillis(time.Since(startedAt))
	}()

	fillReferenceInfo(&result, image)

	resolveStartedAt := time.Now()
	digest, err := registry.ResolveDigest(ctx, image, authCfg)
	result.ResolveMillis = durationMillis(time.Since(resolveStartedAt))
	if err != nil {
		if isTimeoutError(err) {
			result.ProvenanceStatus = "timeout"
			result.ProvenanceError = err.Error()
			result.Notes = append(result.Notes, "per-image timeout exceeded during digest resolution")
			return result
		}
		result.ProvenanceStatus = classifyResolveStatus(err)
		result.ProvenanceError = err.Error()
		result.Notes = append(result.Notes, presentationNote(result.ProvenanceStatus))
		return result
	}

	result.ResolvedDigest = digest
	result.DigestRef = digestRef(image, digest)

	attestationStartedAt := time.Now()
	report, err := attestation.InspectImageAttestations(ctx, result.DigestRef, authCfg)
	result.AttestationMillis = durationMillis(time.Since(attestationStartedAt))
	if report != nil {
		result.AttestationCount = len(report.Attestations)
		result.SigningMethod = report.SigningMethod
		applyAttestationDetails(&result, report.Attestations)
	}
	if err != nil {
		if isTimeoutError(err) {
			result.ProvenanceStatus = "timeout"
			result.ProvenanceError = err.Error()
			result.Notes = append(result.Notes, "per-image timeout exceeded during provenance inspection")
			result.Score = score(result)
			return result
		}
		result.ProvenanceStatus = report.Status
		result.ProvenanceError = report.Error
		result.Notes = append(result.Notes, presentationNote(report.Status))
		enrichSBOMAndVulnerabilities(ctx, &result)
		result.Score = score(result)
		return result
	}

	result.ProvenanceVerified = report.Verified
	result.ProvenanceStatus = report.Status
	enrichSBOMAndVulnerabilities(ctx, &result)
	result.Score = score(result)

	if result.Score == 0 {
		result.Notes = append(result.Notes, "no verifiable provenance signal")
	}

	return result
}

func isTimeoutError(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "context deadline exceeded") ||
		strings.Contains(msg, "deadline exceeded") ||
		strings.Contains(msg, "operation timed out")
}

func classifyResolveStatus(err error) string {
	msg := strings.ToLower(err.Error())

	switch {
	case strings.Contains(msg, "requested access to the resource is denied"),
		strings.Contains(msg, "authentication required"),
		strings.Contains(msg, "insufficient_scope"),
		strings.Contains(msg, "unauthorized"),
		strings.Contains(msg, "denied"):
		return "auth_required"
	case strings.Contains(msg, "rate limit"),
		strings.Contains(msg, "too many requests"),
		strings.Contains(msg, "toomanyrequests"):
		return "registry_error"
	case strings.Contains(msg, "temporary failure"),
		strings.Contains(msg, "connection refused"),
		strings.Contains(msg, "no such host"),
		strings.Contains(msg, "unreachable"):
		return "unavailable"
	default:
		return "resolve_error"
	}
}

func fillReferenceInfo(result *ImageResult, image string) {
	ref, err := name.ParseReference(image)
	if err != nil {
		result.Notes = append(result.Notes, "invalid image reference")
		return
	}

	result.Registry = ref.Context().RegistryStr()
	result.Repository = ref.Context().RepositoryStr()

	repoParts := strings.Split(result.Repository, "/")
	switch {
	case len(repoParts) == 0:
		return
	case len(repoParts) == 1:
		result.Publisher = "library"
	default:
		result.Publisher = repoParts[0]
	}
}

func digestRef(image, digest string) string {
	base, _, _ := strings.Cut(image, "@")
	return fmt.Sprintf("%s@%s", base, digest)
}

func applyAttestationDetails(result *ImageResult, atts []attestation.VerifiedAttestation) {
	predicateTypes := make([]string, 0, len(atts))
	subjects := make([]string, 0, len(atts))
	issuers := make([]string, 0, len(atts))

	for _, att := range atts {
		if att.PredicateType != "" {
			predicateTypes = appendUnique(predicateTypes, att.PredicateType)
		}
		if att.Subject != "" {
			subjects = appendUnique(subjects, att.Subject)
		}
		if att.Issuer != "" {
			issuers = appendUnique(issuers, att.Issuer)
		}
		if att.RekorEntryPresent {
			result.RekorEntryPresent = true
		}
		if result.SourceRepo == "" && att.SourceRepo != "" {
			result.SourceRepo = att.SourceRepo
			result.SourceRepoLinked = true
		}
		if result.BuilderID == "" && att.BuilderID != "" {
			result.BuilderID = att.BuilderID
		}
		if result.WorkflowRef == "" && att.WorkflowRef != "" {
			result.WorkflowRef = att.WorkflowRef
		}
	}

	result.PredicateTypes = predicateTypes
	result.SubjectIdentities = subjects
	result.Issuers = issuers
	result.Score = score(*result)
}

func summarize(results []ImageResult) Summary {
	var summary Summary
	summary.Total = len(results)

	for _, result := range results {
		if result.ProvenanceVerified {
			summary.Verified++
		}
		if result.RekorEntryPresent {
			summary.WithRekor++
		}
		if result.SourceRepoLinked {
			summary.WithSourceRepo++
		}
		if result.BuilderID != "" {
			summary.WithBuilderID++
		}
		if len(result.PredicateTypes) > 0 {
			summary.WithProvenanceSignal++
		}
		if result.SBOMAvailable {
			summary.WithSBOM++
		}
		if result.VulnerabilityScan == "completed" {
			summary.WithVulnerabilityScan++
		}
		if result.CriticalCount > 0 {
			summary.ImagesWithCritical++
		}
		summary.TotalVulnerabilities += result.VulnerabilityTotal
	}

	return summary
}

func enrichSBOMAndVulnerabilities(ctx context.Context, result *ImageResult) {
	sbomStartedAt := time.Now()
	resolvedSBOM, err := sbom.ExtractSBOM(ctx, result.DigestRef)
	result.SBOMMillis = durationMillis(time.Since(sbomStartedAt))
	if err != nil {
		if isTimeoutError(err) {
			result.VulnerabilityScan = "timeout"
			result.VulnerabilityError = err.Error()
			result.Notes = append(result.Notes, "per-image timeout exceeded during sbom extraction")
			return
		}
		result.Notes = append(result.Notes, "sbom extraction failed")
		result.VulnerabilityScan = "sbom_failed"
		result.VulnerabilityError = err.Error()
		return
	}

	result.SBOMAvailable = true
	result.SBOMSource = string(resolvedSBOM.Source)
	result.SBOMFormat = resolvedSBOM.Format
	result.PackageCount = len(resolvedSBOM.Packages)

	vulnerabilityStartedAt := time.Now()
	findings, err := vuln.ScanNormalizedPackagesWithOSV(ctx, vuln.NewOSVClient(), resolvedSBOM.Packages, vuln.ScanOptions{
		RequireVersion: true,
		RequirePURL:    true,
	})
	result.VulnerabilityMillis = durationMillis(time.Since(vulnerabilityStartedAt))
	if err != nil {
		if isTimeoutError(err) {
			result.VulnerabilityScan = "timeout"
			result.VulnerabilityError = err.Error()
			result.Notes = append(result.Notes, "per-image timeout exceeded during vulnerability scan")
			return
		}
		result.VulnerabilityScan = "scan_error"
		result.VulnerabilityError = err.Error()
		result.Notes = append(result.Notes, "vulnerability scan failed")
		return
	}

	summary := vuln.Summarize(findings)
	result.VulnerabilityScan = "completed"
	result.VulnerabilityTotal = summary.Total
	result.CriticalCount = summary.Critical
	result.HighCount = summary.High
	result.MediumCount = summary.Medium
	result.LowCount = summary.Low
	result.UnknownCount = summary.Unknown
}

func durationMillis(d time.Duration) int64 {
	return d.Milliseconds()
}

func score(result ImageResult) int {
	score := 0

	if result.AttestationCount > 0 {
		score = 1
	}
	if result.ProvenanceVerified {
		score = 2
	}
	if len(result.SubjectIdentities) > 0 || len(result.Issuers) > 0 {
		score = 3
	}
	if result.RekorEntryPresent {
		score = 4
	}
	if result.SourceRepoLinked && result.BuilderID != "" {
		score = 5
	}

	return score
}

func appendUnique(values []string, value string) []string {
	if value == "" {
		return values
	}
	for _, existing := range values {
		if existing == value {
			return values
		}
	}

	return append(values, value)
}

func presentationNote(status string) string {
	switch status {
	case "not_found":
		return "no signed provenance attestation found"
	case "verification_incompatible":
		return "attestations discovered but current verifier could not validate their format"
	case "auth_required":
		return "registry requires authentication before provenance can be inspected"
	case "invalid":
		return "attestation exists but verification failed"
	case "auth_error":
		return "registry authentication blocked verification"
	case "registry_error":
		return "registry refused or rate-limited the request"
	case "unavailable":
		return "verification dependency unavailable"
	default:
		return "provenance check did not complete"
	}
}
