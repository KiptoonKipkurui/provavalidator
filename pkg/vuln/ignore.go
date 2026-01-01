package vuln

import (
	"os"

	"gopkg.in/yaml.v3"
)

type IgnoreFile struct {
	Ignore []struct {
		VulnID string `yaml:"vulnId"`
		Reason string `yaml:"reason"`
	} `yaml:"ignore"`
}

func LoadIgnoreFile(path string) (map[string]struct{}, error) {
	if path == "" {
		return make(map[string]struct{}), nil
	}

	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f IgnoreFile

	if err := yaml.Unmarshal(b, &f); err != nil {
		return nil, err
	}

	out := map[string]struct{}{}

	for _, i := range f.Ignore {
		out[i.VulnID] = struct{}{}
	}
	return out, nil
}

func FilterIgnored(findings []Finding, ignored map[string]struct{}) []Finding {
	if len(ignored) == 0 {
		return findings
	}

	out := make([]Finding, 0, len(findings))
	for _, f := range findings {
		if _, ok := ignored[f.VulnID]; ok {
			continue
		}
		out = append(out, f)
	}
	return out
}
