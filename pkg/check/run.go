package check

import (
	"context"
	"fmt"

	"github.com/kiptoonkipkurui/provavalidator/pkg/attestation"
	"github.com/kiptoonkipkurui/provavalidator/pkg/drift"
	"github.com/kiptoonkipkurui/provavalidator/pkg/registryauth"
	"github.com/kiptoonkipkurui/provavalidator/pkg/sbom"
	"github.com/kiptoonkipkurui/provavalidator/pkg/vuln"
)

type Options struct {
	Image string
	// Provenence
	RequireProvenance bool

	// Vulnerabilities
	FailOnSeverity string
	IgnoreFile     string

	// Drift
	Baseline     string
	FailOnDrift  bool
	AllowExtra   bool
	AllowMissing bool
	AllowReorder bool
	AuthCfg      *registryauth.Config
}

type PolicyViolationError struct{ Msg string }

func (e PolicyViolationError) Error() string {
	return e.Msg
}

type OperationalError struct{ Err error }

func (e OperationalError) Error() string {
	return e.Err.Error()
}
func (e OperationalError) Unwrap() error {
	return e.Err
}

func Run(ctx context.Context, opt Options) (*Result, error) {

	out := &Result{
		Image: opt.Image,
	}

	// 1. Provenence
	out.Provenence.Required = opt.RequireProvenance

	if opt.RequireProvenance {

		_, err := attestation.VerifyImageAttestations(ctx, out.Image, opt.AuthCfg)
		if err != nil {
			out.Provenence.Passed = false
			out.Provenence.Message = err.Error()
			return out, PolicyViolationError{Msg: "provenence required but not satisfied"}
		} else {
			out.Provenence.Passed = true
		}
	}

	// 2. SBOM + vulnerabilities
	sbomMeta, err := sbom.ExtractSBOM(ctx, opt.Image)
	if err != nil {
		return out, OperationalError{Err: fmt.Errorf("SBOM generation error %w", err)}
	}
	findings, _ := vuln.ScanVulnerabilities(ctx, opt.Image)

	ignored, err := vuln.LoadIgnoreFile(opt.IgnoreFile)
	if err != nil {
		return out, OperationalError{Err: fmt.Errorf("ingore file loading error %w", err)}
	}
	// filter out ignored vulnerabilities
	findings = vuln.FilterIgnored(findings, ignored)
	out.SBOM.Packages = sbomMeta
	out.Vuln.Findings = findings

	out.Vuln.Summary = vuln.Summarize(findings)
	out.Vuln.FailOn = opt.FailOnSeverity

	if opt.FailOnSeverity != "" {
		min, err := vuln.ParseSeverity(opt.FailOnSeverity)

		if err != nil {
			return out, OperationalError{Err: err}
		}
		out.Vuln.Violations = vuln.FilterBySeverity(findings, min)
		if len(out.Vuln.Violations) > 0 {
			out.Passed = false
			return out, PolicyViolationError{Msg: "vulnerability policy violation "}
		}
	}

	if opt.Baseline != "" {
		out.Drift.Baseline = opt.Baseline

		res, err := drift.DetectLayerDrift(ctx, opt.Image, out.Drift.Baseline)

		if err != nil {
			return out, OperationalError{Err: fmt.Errorf("drift detection error %w", err)}
		}
		out.Drift.Result = res

		p := drift.Policy{
			FailOnDrift:  opt.FailOnDrift,
			AllowExtra:   opt.AllowExtra,
			AllowMissing: opt.AllowMissing,
			AllowReorder: opt.AllowReorder,
		}

		if err := drift.EvaluatePolicy(res, p); err != nil && opt.FailOnDrift {
			out.Drift.PolicyFail = true
			out.Drift.Message = err.Error()
			out.Passed = false
			return out, PolicyViolationError{Msg: "drift policy violated"}
		}
	}
	out.Passed = true

	return out, nil
}
