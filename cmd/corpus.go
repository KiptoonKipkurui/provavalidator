package cmd

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/kiptoonkipkurui/provavalidator/pkg/research"
	"github.com/kiptoonkipkurui/provavalidator/pkg/sbom"
	"github.com/spf13/cobra"
)

var (
	corpusFile        string
	corpusOutput      string
	corpusFormat      string
	corpusConcurrency int
	corpusTimeout     time.Duration
)

var corpusCmd = &cobra.Command{
	Use:   "corpus [IMAGE...]",
	Short: "Run provenance research across a corpus of container images",
	RunE: func(cmd *cobra.Command, args []string) error {
		images, err := loadCorpusInputs(corpusFile, args)
		if err != nil {
			return err
		}
		if len(images) == 0 {
			return fmt.Errorf("no images supplied; pass IMAGE arguments or --images-file")
		}

		ctx := sbom.WithRuntimeConfig(cmd.Context(), appCtx.AuthConfig.Runtime)
		result, err := research.Run(ctx, research.Options{
			Images:       images,
			AuthCfg:      appCtx.AuthConfig,
			Concurrency:  corpusConcurrency,
			ImageTimeout: corpusTimeout,
		})
		if err != nil {
			return err
		}

		return writeCorpusOutput(result, corpusFormat, corpusOutput)
	},
}

func init() {
	corpusCmd.Flags().StringVar(&corpusFile, "images-file", "", "Path to a newline-delimited image corpus file")
	corpusCmd.Flags().StringVar(&corpusOutput, "output", "", "Write results to this file instead of stdout")
	corpusCmd.Flags().StringVar(&corpusFormat, "format", "text", "Output format (text|json|csv)")
	corpusCmd.Flags().IntVar(&corpusConcurrency, "concurrency", 4, "Number of images to process in parallel")
	corpusCmd.Flags().DurationVar(&corpusTimeout, "image-timeout", 90*time.Second, "Per-image timeout")
	rootCmd.AddCommand(corpusCmd)
}

func loadCorpusInputs(path string, args []string) ([]string, error) {
	images := append([]string(nil), args...)
	if path == "" {
		return images, nil
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		images = append(images, line)
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return images, nil
}

func writeCorpusOutput(result *research.CorpusResult, format, outputPath string) error {
	out := os.Stdout
	if outputPath != "" {
		file, err := os.Create(outputPath)
		if err != nil {
			return err
		}
		defer file.Close()
		out = file
	}

	switch strings.ToLower(format) {
	case "json":
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(result)
	case "csv":
		return research.WriteCSV(out, result)
	case "text", "":
		printCorpusText(out, result)
		return nil
	default:
		return fmt.Errorf("unsupported format %q (use text, json, or csv)", format)
	}
}

func printCorpusText(out io.Writer, result *research.CorpusResult) {
	fmt.Fprintf(out, "Images tested: %d\n", result.Summary.Total)
	fmt.Fprintf(out, "Verified provenance: %d\n", result.Summary.Verified)
	fmt.Fprintf(out, "With Rekor entry: %d\n", result.Summary.WithRekor)
	fmt.Fprintf(out, "With source repo: %d\n", result.Summary.WithSourceRepo)
	fmt.Fprintf(out, "With builder ID: %d\n\n", result.Summary.WithBuilderID)
	fmt.Fprintf(out, "With SBOM: %d\n", result.Summary.WithSBOM)
	fmt.Fprintf(out, "With vulnerability scan: %d\n", result.Summary.WithVulnerabilityScan)
	fmt.Fprintf(out, "Images with critical vulns: %d\n", result.Summary.ImagesWithCritical)
	fmt.Fprintf(out, "Total vulnerabilities: %d\n\n", result.Summary.TotalVulnerabilities)

	for _, image := range result.Images {
		fmt.Fprintf(out, "- %s\n", image.ImageRef)
		fmt.Fprintf(out, "  status=%s score=%d digest=%s\n", image.ProvenanceStatus, image.Score, image.ResolvedDigest)
		if image.SourceRepo != "" {
			fmt.Fprintf(out, "  source=%s\n", image.SourceRepo)
		}
		if image.BuilderID != "" {
			fmt.Fprintf(out, "  builder=%s\n", image.BuilderID)
		}
		if image.SBOMAvailable {
			fmt.Fprintf(out, "  sbom=%s source=%s packages=%d\n", image.SBOMFormat, image.SBOMSource, image.PackageCount)
		}
		if image.VulnerabilityScan != "" && image.VulnerabilityScan != "not_run" {
			fmt.Fprintf(out, "  vuln_scan=%s total=%d critical=%d high=%d medium=%d low=%d unknown=%d\n",
				image.VulnerabilityScan,
				image.VulnerabilityTotal,
				image.CriticalCount,
				image.HighCount,
				image.MediumCount,
				image.LowCount,
				image.UnknownCount,
			)
		}
		if len(image.PredicateTypes) > 0 {
			fmt.Fprintf(out, "  predicates=%s\n", strings.Join(image.PredicateTypes, ", "))
		}
		if image.ProvenanceError != "" {
			fmt.Fprintf(out, "  provenance_error=%s\n", image.ProvenanceError)
		}
		if image.VulnerabilityError != "" {
			fmt.Fprintf(out, "  vulnerability_error=%s\n", image.VulnerabilityError)
		}
	}
}
