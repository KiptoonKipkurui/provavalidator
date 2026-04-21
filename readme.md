# provavalidator

**provavalidator** is a Go-based **container supply-chain validator** designed for CI/CD pipelines.

It goes beyond traditional image scanners by **making explicit allow/block decisions** based on:

- how an image was built (provenance)
- what it contains (SBOM)
- what risks it introduces (vulnerabilities)
- whether it has changed unexpectedly (layer drift)

The goal is simple: **prevent untrusted or non-compliant container images from entering production**.

---

## Why provavalidator?

Most container security tools today:
- scan images
- generate reports
- rely on humans to interpret results

This does not scale.

`provavalidator` is built around a different idea:

> **Security tools should decide, not just inform.**

It is designed to run inside CI/CD (especially GitHub Actions) and act as a **policy gate**, failing builds when expectations are violated.

---

## What provavalidator validates

### 1. Image provenance
- Verifies signed attestations (SLSA / in-toto)
- Confirms builder identity and integrity
- Treats missing provenance as a **signal**, not an error

### 2. Software Bill of Materials (SBOM)
- Parses CycloneDX and SPDX SBOMs
- Currently generates SBOMs locally with **Syft** during image checks
- Normalizes decoded SBOM content into a stable internal model
- Signed SBOM attestation resolution is planned but not implemented yet

### 3. Vulnerabilities
- Correlates SBOM packages with **OSV**
- Uses batch and parallel queries for performance
- Normalizes severity (Low → Critical)
- Supports ignore files for accepted risks

### 4. Layer drift
- Compares **uncompressed layer DiffIDs**
- Detects:
  - tag mutation
  - rebuilt images with different filesystem content
  - extra, missing, or reordered layers
- Uses DiffIDs (filesystem truth), not compressed digests

### 5. Policy enforcement
- Fail builds based on:
  - vulnerability severity
  - provenance expectations
  - layer drift
- Designed for deterministic CI behavior

---

## Architecture overview

Container Image
├─ Provenance (attestations)
├─ SBOM (currently generated locally)
├─ Layer DiffIDs
└─ Packages
↓
Vulnerability Correlation (OSV)
↓
Policy Engine
↓
CI/CD Decision


Key design principles:
- trust-first resolution
- explicit fallbacks
- deterministic output
- CI-friendly failures

---

## Installation

### Download a release binary

```bash
curl -L https://github.com/kiptoonkipkurui/provavalidator/releases/latest/download/provavalidator-linux-amd64 \
  -o provavalidator
chmod +x provavalidator
sudo mv provavalidator /usr/local/bin/
```

BUild from source

```bash
git clone https://github.com/kiptoonkipkurui/provavalidator.git
cd provavalidator
go build ./cmd/provavalidator

```
Note: The binary includes a pure-Go SQLite driver (modernc.org/sqlite) to support RPM-based images.

Usage
Scan vulnerabilities

```bash
provavalidator vuln ghcr.io/org/app:1.2.3
```

Example output:

```yaml
Vulnerability summary:
  Critical: 1
  High:     3
  Medium:   7
  Low:      5
  Total:    16
```

Fail CI on high-severity issues

```bash
provavalidator vuln ghcr.io/org/app:1.2.3 --fail-on-high
```

If policy is violated:

- exit code = 1
- blocking vulnerabilities are printed
- GitHub PR annotations are emitted (when running in Actions)

### Ignore Known Vulnerabilities

Create an ignore file: 
```yaml
# .provavalidator-ignore.yaml
ignore:
  - vulnId: OSV-2025-1234
    reason: "False positive in statically linked binary"

```

Run

```bash
provavalidator vuln IMAGE --ignore-file .provavalidator-ignore.yaml

```
### Detect layer drift
Compare a mutable tag against a pinned baseline:

```bash
provavalidator drift \
  ghcr.io/org/app:latest \
  ghcr.io/org/app@sha256:abcd...

```

Example output:

```yaml
Layer drift detected

Changed layers:
  - index 2
    expected: sha256:aaa…
    actual:   sha256:bbb…

Extra layers:
  - sha256:ccc…

```
This detects:

- tag mutation

- unexpected rebuilds

- filesystem changes masked by identical tags


### JSON output (machine readable)

```bash
provavalidator vuln IMAGE --format json

```
Useful for: 
- CI artifacts
- dashboards
- audits


### GitHub Action

`provavalidator` can now run as either:
- a standalone CLI
- a reusable GitHub Action

The Action builds the project from source in the action workspace and then runs the existing CLI underneath, so the Action and CLI stay aligned.

Supported Action modes:
- `check`
- `vuln`
- `drift`
- `attest`
- `corpus`
- `args` for raw CLI arguments

Minimal `check` example:

```yaml
name: Supply Chain Validation

on:
  pull_request:
  push:
    branches: [main]

jobs:
  validate:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4

      - name: Validate built image
        uses: kiptoonkipkurui/provavalidator@main
        with:
          mode: check
          image: ghcr.io/org/app:${{ github.sha }}
          fail-on: high
          ignore-file: .provavalidator-ignore.yaml
          format: json
```

Drift example:

```yaml
- name: Compare image against approved baseline
  uses: kiptoonkipkurui/provavalidator@main
  with:
    mode: drift
    image: ghcr.io/org/app:${{ github.sha }}
    baseline: ghcr.io/org/app@sha256:abcd1234...
    fail-on-drift: true
```

Corpus / research example:

```yaml
- name: Research image corpus
  uses: kiptoonkipkurui/provavalidator@main
  with:
    mode: corpus
    images-file: configs/research/presentation-images.txt
    concurrency: 4
    image-timeout: 90s
    format: json
    output: results/corpus.json
```

Raw args example:

```yaml
- name: Run custom provavalidator command
  uses: kiptoonkipkurui/provavalidator@main
  with:
    mode: args
    args: check ghcr.io/org/app:${{ github.sha }} --fail-on high --format json
```

Registry auth can be passed the same way as the CLI:

```yaml
- name: Validate private or mixed-visibility registries
  uses: kiptoonkipkurui/provavalidator@main
  env:
    GHCR_TOKEN: ${{ secrets.GHCR_TOKEN }}
    QUAY_USERNAME: ${{ secrets.QUAY_USERNAME }}
    QUAY_PASSWORD: ${{ secrets.QUAY_PASSWORD }}
    ECR_PUBLIC_PASSWORD: ${{ secrets.ECR_PUBLIC_PASSWORD }}
  with:
    mode: corpus
    auth-config: configs/auth.example.yaml
    images-file: configs/research/presentation-images.txt
```

This lets the project work in two ways:
- as a local or CI CLI for direct invocation
- as a GitHub-native Action that wraps the same commands for image build pipelines

### Research a public image corpus

For presentation or policy-design work, you can run provenance checks across a batch of public images and export the results as CSV:

```bash
provavalidator corpus \
  --images-file configs/research/presentation-images.txt \
  --format csv \
  --output results/provenance-study.csv
```

JSON output is also available:

```bash
provavalidator corpus \
  --images-file configs/research/presentation-images.txt \
  --format json
```

The CSV includes image reference, resolved digest, provenance status, signer identity, issuer, predicate types, source repo, builder ID, Rekor presence, and a simple 0-5 maturity score.


### What provavalidator does not do

This tool intentionally does not:

- perform runtime analysis
- detect zero-day vulnerabilities
- guarantee absence of compromise

It provides evidence-based validation, not absolute security.

## Contributing

Contributions are welcome, especially:
- policy rules
- performance improvements
- documentation
- test coverage
Please open an issue before major changes.

## License

MIT License

## Author
Built and maintained by **Daniel Kiptoon**.
email: kiptoonkipkurui@gmail.com

This project grew out of hands-on work with:

- container internals
- supply-chain security
- CI/CD enforcement

If you are interested in discussing or extending this work, feel free to reach out.
