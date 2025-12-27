package registry

import (
	"fmt"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// newFakeImage creates an in-memory image with two layers.
func newFakeImage(t *testing.T) v1.Image {
	t.Helper()
	img, err := random.Image(1024, 2)

	if err != nil {
		t.Fatalf("failed to append layers: %v", err)
	}

	return img
}

func TestFetchImageMetadata_FakeRegistry(t *testing.T) {
	// build fake image
	img := newFakeImage(t)

	// Spin up an in-memory registry server
	srv := httptest.NewServer(registry.New())
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	host := u.Host // "127.0.0.1:43517"
	// Push image into fake registry
	ref, err := name.ParseReference(fmt.Sprintf("%s/test/image:latest", host))
	if err != nil {
		t.Fatalf("parsing ref: %v", err)
	}

	if err := remote.Write(ref, img); err != nil {
		t.Fatalf("writing image to fake registry: %d", err)
	}

	// now test our FetchImageMetadata
	meta, err := FetchImageMetadata(t.Context(), ref.String())
	if err != nil {
		t.Fatalf("FetchImageMetadata failed: %v", err)
	}

	// validate compressed digests (manifest layer digests)
	if len(meta.CompressedLayerDigests) != 2 {
		t.Fatalf("expected 2 compressed layer digests, got %d", len(meta.CompressedLayerDigests))
	}

	// Validate uncompressed DiffIDs
	if len(meta.DiffIDs) != 2 {
		t.Fatalf("expected 2 DiffIDs, got %d", len(meta.DiffIDs))
	}

	// Config digest must not be empty
	if meta.ConfigDigest == "" {
		t.Fatalf("expected nonempty config digest")
	}
}

// Test DiffID and layer digest relationships
func TestDiffIDOrder(t *testing.T) {
	img := newFakeImage(t)

	// Extract values directly via go-containerregistry
	cfg, err := img.ConfigFile()
	if err != nil {
		t.Fatalf("reading config file: %v", err)
	}

	if len(cfg.RootFS.DiffIDs) != 2 {
		t.Fatalf("expected 2 DiffIDs in fake image")
	}

	first := cfg.RootFS.DiffIDs[0]
	second := cfg.RootFS.DiffIDs[1]

	if first == second {
		t.Fatalf("expected Distinct DiffIDs but got identical (%s)", first)
	}
}

// Test compressed vs uncompressed digests correctness
func TestCompressedVsUncompressedDigests(t *testing.T) {
	img := newFakeImage(t)

	manifest, err := img.Manifest()
	if err != nil {
		t.Fatalf("reading manifest: %v", err)
	}

	if len(manifest.Layers) != 2 {
		t.Fatalf("expected 2 compressed layers")
	}

	// Compressed digest must not equal DiffID
	cfg, _ := img.ConfigFile()

	for i := 0; i < 2; i++ {
		if manifest.Layers[i].Digest == cfg.RootFS.DiffIDs[i] {
			t.Fatalf("compressed digest and DiffID should differ for layer %d", i)
		}
	}
}
