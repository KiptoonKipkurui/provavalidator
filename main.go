package main

import (
	"github.com/kiptoonkipkurui/provavalidator/cmd"
)

func main() {
	// attestation.VerifyImageAttestations(context.Background(), "cgr.dev/chainguard/nginx:latest")

	cmd.Execute()
}
