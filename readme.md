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
- Prefers **signed SBOM attestations**
- Falls back to locally generated SBOMs when none are published
- Normalizes all formats into a stable internal model

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
├─ SBOM (attested or generated)
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


### Github Actions example

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

      - name: Install provavalidator
        run: |
          curl -L https://github.com/kiptoonkipkurui/provavalidator/releases/latest/download/provavalidator-linux-amd64 \
            -o provavalidator
          chmod +x provavalidator
          sudo mv provavalidator /usr/local/bin/

      - name: Validate image
        run: |
          provavalidator vuln ghcr.io/org/app:${{ github.sha }} \
            --fail-on high \
            --ignore-file .provavalidator-ignore.yaml
```

This will: 
- block the PR on policy violation
- Surface issues directly in the PR via annotations


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