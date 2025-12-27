package drift

import (
	"context"
	"fmt"
)

func DetectLayerDrift(ctx context.Context, image string) error {
	// TODO: compare layer digests vs baseline
	fmt.Println("[drift] Detecting layer drift for:", image)
	return nil
}
