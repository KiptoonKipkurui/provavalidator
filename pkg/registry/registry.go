package registry

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// imageMetadata represents metadata fetched from a container registry useful for provenance drift.
type ImageMetadata struct {
	// Reference is the textual image reference you passed in (e.g., "ubuntu:latest", "gcr.io/image:tag")
	Reference string

	// ManifestDigest is the digest of the image manifest (or index manifest for multi-arch images) that points to the layers
	ManifestDigest string

	// ConfigDigest is the digest of the image config blob (compressed digest stored in the registry)
	ConfigDigest string

	// CompressedLayerDigests are the digests found in the manifest (these are the registry blob digests)
	CompressedLayerDigests []string

	// DiffIDs are the uncompressed layer digests found in the image config (these represent the filesystem)
	DiffIDs []string

	//  Platform info (filled for images; for multi-arch selection this will reflect the selected platform)
	OS           string
	Architecture string
}

var ErrNotAnImage = errors.New("reference resolved to an index; no suitable platform image found")

// FetchImageMetadata fetches image metadata for the given reference string (image:tag or image@sha256:digest)
// :...).
//
// It will attempt to fetch a platform-specific image when the registry yields an index (multi-arch).
// By default it will select the current runtime platform (runtime.GOOS / runtime.GOARCH). If you need
// another platform, use FetchImageMetadataWithPlatform.

func FetchImageMetadata(ctx context.Context, image string) (*ImageMetadata, error) {

	return FetchImageMetadataWithPlatform(ctx, image, runtime.GOOS, runtime.GOARCH)
}

// FetchImageMetadataWithPlatform fetches metadata but forces a target OS/Arch for selecting a manifest
// out of an index. Use this when you need to examine an image for a different platform (e.g., linux/arm64).
func FetchImageMetadataWithPlatform(ctx context.Context, refStr, osStr, archStr string) (*ImageMetadata, error) {
	// Parse reference (supporting tag or digest)
	ref, err := name.ParseReference(refStr)

	if err != nil {
		return nil, fmt.Errorf("error parsing reference %q: %w ", refStr, err)
	}

	// Default keychain will pick up docker creds or cloud provider creds available in the environment
	keychain := authn.DefaultKeychain

	// Prepare remote options: default keychain and allow selection by platform
	remoteOpts := []remote.Option{
		remote.WithAuthFromKeychain(keychain),
	}

	// Try to fetch image ( if ref points to an image manifest or tag)
	img, err := remote.Image(ref, remoteOpts...)

	if err != nil {
		//If remote fails, it could be because the ref is an index (manifest list)
		idx, idxErr := remote.Index(ref, remoteOpts...)

		if idxErr != nil {
			// not an index either, return the original image error
			return nil, fmt.Errorf("error fetching image %q: %w", refStr, err)
		}

		// we have an index, attempt to pick a manifest for the requested platform
		manif, mfErr := idx.IndexManifest()

		if mfErr != nil {
			return nil, fmt.Errorf("error getting index manifest for %q: %w", refStr, mfErr)
		}
		// find the manigest that matches the requested platform
		var selected *v1.Descriptor
		targetOS := strings.ToLower(osStr)
		targetArch := strings.ToLower(archStr)

		for i := range manif.Manifests {
			m := manif.Manifests[i]
			if m.Platform == nil {
				continue
			}

			if strings.ToLower(m.Platform.OS) == targetOS && strings.ToLower(m.Platform.Architecture) == targetArch {
				selected = &m
				break
			}
		}

		if selected == nil {
			// fallback: try to pick any linux manifest if requested os is linux
			if targetOS == "linux" {
				for i := range manif.Manifests {
					m := manif.Manifests[i]
					if m.Platform == nil {
						continue
					}
					if strings.ToLower(m.Platform.OS) == "linux" {
						selected = &m
						break
					}
				}
			}
		}
		if selected == nil {
			return nil, ErrNotAnImage
		}

		//  Build a digest-specific reference to the selected manifest and fetch that as an image
		repo := ref.Context().Name()
		digestRefStr := fmt.Sprintf("%s@%s", repo, selected.Digest.String())
		digestRef, pErr := name.NewDigest(digestRefStr)
		if pErr != nil {
			return nil, fmt.Errorf("building digest reference %q: %w", digestRefStr, pErr)
		}

		img, err = remote.Image(digestRef, remoteOpts...)
		if err != nil {
			return nil, fmt.Errorf("fetching platform image %s: %w", digestRefStr, err)
		}
		// we will continue and extract metadata from img below
	}

	// At this point we have v1.Image in img
	manifest, err := img.Manifest()
	if err != nil {
		return nil, fmt.Errorf("reading manifest: %w", err)
	}
	cfgName, err := img.ConfigName()

	if err != nil {
		return nil, fmt.Errorf("reading config name: %w", err)
	}
	cfg, err := img.ConfigFile()

	if err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}

	// Convert compressed digests from file
	var compressed []string
	for _, layer := range manifest.Layers {
		compressed = append(compressed, layer.Digest.String())
	}

	// Convert DIffIDs from RootFS

	var diffs []string

	if cfg != nil {
		for _, d := range cfg.RootFS.DiffIDs {
			diffs = append(diffs, d.String())
		}
	}

	// Build result
	meta := &ImageMetadata{
		Reference:              refStr,
		ManifestDigest:         manifest.Config.Digest.String(), // note: manifest.Config is the config descriptor
		ConfigDigest:           cfgName.String(),
		CompressedLayerDigests: compressed,
		DiffIDs:                diffs,
	}

	// fill platform info if available in config
	if cfg != nil && cfg.OS != "" {
		meta.OS = cfg.OS
	}
	if cfg != nil && cfg.Architecture != "" {
		meta.Architecture = cfg.Architecture
	}

	return meta, nil
}

func GetLayerDiffIDs(refStr string) ([]string, error) {
	meta, err := FetchImageMetadata(context.Background(), refStr)

	if err != nil {
		return nil, err
	}

	return meta.DiffIDs, nil
}

// GetCompressedLayerDigests returns the compressed layer digests from the manifest.
func GetCompressedLayerDigests(refStr string) ([]string, error) {
	meta, err := FetchImageMetadata(context.Background(), refStr)
	if err != nil {
		return nil, err
	}
	return meta.CompressedLayerDigests, nil
}
