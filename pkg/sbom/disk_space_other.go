//go:build !unix

package sbom

func freeSpaceBytes(string) (uint64, bool, error) {
	return 0, false, nil
}
