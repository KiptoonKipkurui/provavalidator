package drift

import (
	"context"
	"fmt"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

type DriftResult struct {
	Drifted  bool
	Expected []v1.Hash
	Actual   []v1.Hash
	Missing  []v1.Hash
	Extra    []v1.Hash
	Changed  []LayerChange
}

type LayerChange struct {
	Index    int
	Expected v1.Hash
	Actual   v1.Hash
}

func DetectLayerDrift(ctx context.Context, image string, baseline string) (*DriftResult, error) {
	// TODO: compare layer digests vs baseline

	actual, err := getDiffIDs(ctx, image)

	if err != nil {
		return nil, fmt.Errorf("fetch actual image diffIDs: %w", err)
	}

	expected, err := getDiffIDs(ctx, baseline)
	if err != nil {
		return nil, fmt.Errorf("fetch expected image diffIDs: %w", err)
	}

	res := &DriftResult{
		Expected: expected,
		Actual:   actual,
	}

	max := len(expected)

	if len(actual) > max {
		max = len(actual)
	}

	for i := 0; i < max; i++ {

		switch {
		case i >= len(expected):
			res.Extra = append(res.Extra, actual[i])
			res.Drifted = true
		case i >= len(actual):
			res.Missing = append(res.Missing, expected[i])
			res.Drifted = true
		case expected[i] != actual[i]:
			res.Drifted = true
			res.Changed = append(res.Changed, LayerChange{
				Index:    i,
				Expected: expected[i],
				Actual:   actual[i],
			})
		}
	}

	return res, nil
}

func getDiffIDs(ctx context.Context, imageRef string) ([]v1.Hash, error) {
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return nil, err
	}
	img, err := remote.Image(ref, remote.WithContext(ctx))

	if err != nil {
		return nil, err
	}

	cfg, err := img.ConfigFile()

	if err != nil {
		return nil, err
	}

	if cfg.RootFS.Type != "layers" {
		return nil, fmt.Errorf("unsupported RootFS type: %s", cfg.RootFS.Type)
	}

	return cfg.RootFS.DiffIDs, nil
}
