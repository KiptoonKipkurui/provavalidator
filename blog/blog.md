*A practical journey through images, provenance, SBOMs, vulnerabilities, drift, and CI enforcement*

---

## Introduction

Containers have become the universal unit of software delivery. We pull images, deploy them to production, and trust that what we are running is what we intended to run.

That trust is often implicit.

This blog documents my journey building **provavalidator**, a Go-based **container supply-chain validator** that does more than scan images. The project grew into two things at once:

- a CLI for validating individual images in CI/CD
- a research tool for measuring how real public container ecosystems behave

That second part turned out to be just as important as the first.

Once I started testing across registries, publishers, and image types, I stopped thinking about provenance as a binary feature and started thinking about it as a spectrum of trust signals with lots of real-world gaps.

---

## Part 1 — Why Container Supply-Chain Security Is Broken

Most container security workflows are reactive:

- scan an image
- produce a report
- hope someone reads it

That does not scale.

Modern software supply chains are:

- automated
- distributed
- dependency-heavy
- registry-driven
- fast

If a tool only informs, the human becomes the policy engine. In practice that means inconsistent decisions, delayed action, and alert fatigue.

What I wanted instead was a validator that could answer:

- Was this image built by a trusted system?
- Do I know what is inside it?
- Does it violate policy?
- Has it changed unexpectedly?

That framing shaped the whole project.

---

## Part 2 — What Is Actually Inside a Container Image?

Before validating anything, I had to understand what an OCI image really is.

A container image is a content-addressed structure made of:

- a manifest
- a config object
- a set of layers

Two digest concepts matter:

### Compressed layer digests

- live in the manifest
- represent the registry-distributed blobs
- are useful for transport and registry-level identity

### Uncompressed layer digests (DiffIDs)

- live in the config
- represent actual filesystem content
- are what matter for drift detection

This distinction is easy to miss, but it becomes crucial.

If two images have the same DiffIDs in the same order, their filesystem contents are effectively the same even if the compressed blobs differ.

That is why drift detection in `provavalidator` uses DiffIDs instead of compressed layer digests.

---

## Part 3 — Provenance: Trusting How an Image Was Built

Provenance asks:

> Who built this image, and can I verify that claim?

In practice that means working with:

- in-toto statements
- SLSA provenance
- Sigstore/Cosign signatures
- Rekor transparency log entries
- builder and issuer identities

The happy-path demo is simple:

- fetch attestation
- verify signature
- extract predicate metadata

The real world is not that simple.

I found several cases:

- images with no provenance at all
- images with attestations but no useful identity context
- images with rich metadata that older verifier paths could not validate correctly
- registries that blocked access before provenance could even be inspected

One of the most useful lessons from this project was:

> Absence of provenance is not the same as invalid provenance, and tooling incompatibility is not the same as publisher failure.

That distinction led me to separate statuses like:

- `not_found`
- `verification_incompatible`
- `auth_required`
- `registry_error`
- `timeout`

That ended up being much more valuable than a naive pass/fail model.

---

## Part 4 — SBOMs: Making Software Transparent

An SBOM is not a security verdict. It is an inventory.

It tells you:

- which packages exist
- which versions are present
- which ecosystems they belong to
- how they can be referenced downstream

I had to normalize different SBOM formats into one internal shape so the rest of the system did not care whether the source was:

- SPDX
- CycloneDX
- Syft JSON

The normalized representation is intentionally small:

```go
type NormalizedPackage struct {
    Name     string
    Version  string
    Type     string
    PURL     string
}
```

That normalization step made the rest of the project much easier. Once packages are stable, vulnerability scanning and policy logic become portable across SBOM formats.

---

## Part 5 — Resolving SBOMs the Right Way

One thing I learned quickly:

> Not every image publishes an SBOM.

So the project needed a resolution strategy rather than a single source of truth.

The approach became:

1. use a signed SBOM attestation when available
2. fall back to generating an SBOM locally

That distinction matters enough that I track it explicitly:

```go
type SourceType string

const (
    SourceAttestation SourceType = "attestation"
    SourceGenerated   SourceType = "generated"
)
```

A generated SBOM is still useful, especially for research, but it should not be confused with publisher-provided signed metadata.

This became one of the major themes of the project:

> metadata source matters almost as much as metadata content.

---

## Part 6 — Vulnerability Scanning with OSV

Once the image contents are normalized, vulnerability scanning becomes a package-to-advisory mapping problem.

I chose **OSV** because it:

- understands ecosystems
- supports batching
- handles version-aware matching better than naive CVE list lookups

The flow is:

1. extract or generate an SBOM
2. normalize packages
3. construct OSV queries
4. map results back to packages
5. summarize severity

Severity is normalized into buckets like `low`, `medium`, `high`, and `critical`.

An important observation from the research runs:

- vulnerability lookup itself was usually not the dominant phase
- SBOM generation was often more expensive than OSV querying

That mattered later when I began tuning execution timeouts.

---

## Part 7 — Drift Detection: Has the Image Changed Unexpectedly?

Another goal of the project was **drift detection**.

The current drift implementation compares filesystem-oriented layer DiffIDs between:

- an image under inspection
- a baseline image

It can detect:

- changed layers
- extra layers
- missing layers

This matters because mutable tags can hide substantial changes. Two tags may have the same human-readable name while representing different underlying filesystems.

Drift is conceptually different from provenance, SBOM, and vulnerabilities because it requires a comparison target. That means drift naturally fits:

- CI enforcement against a pinned baseline
- release validation
- golden-image policy

and less naturally fits completely open-ended public corpus research unless you supply a baseline mapping.

That is the next major evolution I would make to the research pipeline.

---

## Part 8 — Researching Real Public Images

At some point the project stopped being only a validator and became a measurement tool.

I added a `corpus` command so I could test many images across registries and answer questions like:

- how many public images have verifiable provenance?
- which registries expose richer metadata?
- how often are SBOMs available?
- how much of the process completes inside a realistic CI timeout budget?

The corpus grew into a registry-diverse list including:

- Docker Hub official images
- Distroless
- Chainguard
- GitHub Container Registry
- Amazon ECR Public
- Quay
- Microsoft Container Registry
- security-focused publishers like Aqua, Anchore, Falco, and Sigstore

This was one of the most valuable additions to the project because it changed the presentation from:

> “Here is a tool I built.”

to:

> “Here is what the ecosystem actually looks like when a validator is applied to real images.”

---

## Part 9 — What the Corpus Actually Showed

The public-image results were revealing.

Across my expanded corpus, a few patterns stood out consistently:

### 1. Distroless and Chainguard were the strongest provenance examples

They were repeatedly:

- keyless
- Rekor-backed
- attestation-rich
- verifiable with the improved DSSE-aware path

### 2. Mainstream base images often had weak or absent provenance

Many popular Docker Hub images came back as:

- `not_found`

That does not mean they are malicious. It means verifiable provenance is still uneven in practice.

### 3. Registry access is part of the experiment

Some failures had nothing to do with trust metadata and everything to do with registry behavior:

- GHCR images that required auth for digest resolution
- broken or nonexistent `latest` tags on some Quay and ECR references
- inconsistent anonymous access patterns

This ended up being a useful presentation point:

> A supply-chain validator does not operate in a vacuum. Registry behavior is part of the trust story.

### 4. SBOM and vulnerability results changed materially with timeout tuning

At a `60s` per-image timeout, the corpus still produced useful results, but some larger images timed out in SBOM/vulnerability work.

At `90s`, more borderline images completed, and the vulnerability totals increased significantly.

That means timeout choice is not just an implementation detail. It affects the quality of the resulting security data.

---

## Part 10 — Performance Tuning: Worker Pools and Time Budgets

Once the corpus gained provenance, SBOM, and vulnerability stages, it became too slow to run strictly sequentially.

I introduced:

- a bounded worker pool
- configurable corpus concurrency
- a single per-image timeout

The worker pool improved throughput without letting one image block the entire dataset.

The timeout model matters too. I originally experimented with different warm-up and steady-state values, but simplified it to a single `--image-timeout` because what I really needed first was a baseline.

That made empirical tuning easier:

- `60s` gave meaningful results
- `90s` gave better completion for larger images

This was a good reminder that the right timeout should be learned from data, not guessed upfront.

---

## Part 11 — Measuring Where Time Goes

To answer a practical question:

> What is actually consuming the time?

I instrumented the corpus output with per-image phase timings:

- `resolve_ms`
- `attestation_ms`
- `sbom_ms`
- `vulnerability_ms`
- `total_ms`

That made it possible to see which phases dominated.

A few representative examples:

### `ubuntu:latest`

- resolve: ~2.9s
- attestation: ~8.0s
- SBOM: ~12.3s
- vulnerability lookup: ~0.5s
- total: ~23.8s

### `gcr.io/distroless/static-debian12:latest`

- resolve: ~2.7s
- attestation: ~6.0s
- SBOM: ~7.5s
- vulnerability lookup: ~0.4s
- total: ~16.6s

### `ghcr.io/aquasecurity/trivy:latest`

- resolve: ~3.0s
- attestation: ~4.6s
- SBOM: ~18.5s
- vulnerability lookup: ~2.4s
- total: ~28.6s

The pattern was clear:

- SBOM generation was often the largest single cost
- provenance/attestation work was usually second
- vulnerability lookups were comparatively smaller, though they grew with package count

That made performance tuning much more grounded.

---

## Part 12 — Registry Authentication Is Part of the Product

One of the more subtle upgrades was in registry auth handling.

The project was intended to work in two ways:

- access private registries when credentials are available
- still access public images on those same registries without requiring auth

To support that, I added auth modes with anonymous fallback, such as:

- `token_or_anonymous`
- `basic_or_anonymous`
- `docker_or_anonymous`

This was especially relevant for:

- GHCR
- Quay
- ECR Public

That change improved the honesty of the corpus output too. Instead of flattening everything into generic failures, the tool can now separate:

- `auth_required`
- `registry_error`
- `resolve_error`

This made the corpus more useful as a measurement instrument and more credible as research material.

---

## Part 13 — GitHub Actions: From CLI to CI Primitive

From the start, the project was meant to be more than a local CLI.

I added a reusable GitHub Action wrapper so the project can run in two forms:

- as a command-line tool
- as a GitHub Action that builds and invokes the CLI

The Action supports multiple modes:

- `check`
- `vuln`
- `drift`
- `attest`
- `corpus`
- `args` for raw CLI passthrough

That means the same project can be used for:

- build gating
- release validation
- image comparison
- research corpus generation

without having separate implementations for CI and local use.

This was important architecturally: the Action is not a different product. It is a thin wrapper around the same CLI behavior.

---

## Part 14 — CI for the Project Itself

Since the validator is meant to be production-facing, its own repository needed better CI too.

I upgraded the GitHub workflows to include standard Go checks:

- `gofmt`
- `go vet`
- `go build ./...`
- `go test ./...`
- `golangci-lint`
- `govulncheck`

I also added a release workflow for tagged builds so the project can publish binaries in a more standard way.

That may sound secondary, but it matters:

> a supply-chain tool should take its own supply chain seriously.

---

## Part 15 — What This Project Still Does Not Solve

It is important to stay honest.

`provavalidator` does not:

- detect zero-days
- analyze runtime behavior
- guarantee absence of compromise
- prove that unsigned images are safe

It is a policy-oriented validator built around evidence:

- provenance
- contents
- vulnerability data
- layer consistency

That evidence can be strong or weak. The job of the tool is to make that explicit and actionable.

---

## Conclusion

What started as a provenance validator became a broader supply-chain research and enforcement tool.

The most useful thing I learned was this:

> trust in container images is not binary.

An image can be:

- widely used but weakly verifiable
- signed but not policy-ready
- rich in metadata but hard to validate with older tooling
- easy to inventory but expensive to analyze at scale

The project now reflects that reality more honestly.

It can:

- validate provenance
- resolve or generate SBOMs
- scan vulnerabilities
- detect drift
- run as a CLI
- run as a GitHub Action
- and measure these properties across a large corpus of public images

That combination made the project much more useful, and it made the presentation stronger too.

Instead of saying:

> “I built a validator.”

I can now say:

> “I built a validator, used it to study real container ecosystems, and learned where trust signals are strong, weak, missing, or operationally hard to use.”

That is a much more interesting story.
