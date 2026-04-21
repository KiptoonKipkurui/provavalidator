package attestation

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/go-openapi/runtime"
	httptransport "github.com/go-openapi/runtime/client"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/in-toto/in-toto-golang/in_toto"
	"github.com/kiptoonkipkurui/provavalidator/pkg/registryauth"
	"github.com/sigstore/cosign/cmd/cosign/cli/fulcio"
	cosignoptions "github.com/sigstore/cosign/cmd/cosign/cli/options"
	cosignrekor "github.com/sigstore/cosign/cmd/cosign/cli/rekor"
	cosign "github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/cosign/pkg/oci"
	ociremote "github.com/sigstore/cosign/pkg/oci/remote"
	generatedclient "github.com/sigstore/rekor/pkg/generated/client"
	rekormodels "github.com/sigstore/rekor/pkg/generated/models"
	rekortypes "github.com/sigstore/rekor/pkg/types"
	dsse_v001 "github.com/sigstore/rekor/pkg/types/dsse/v0.0.1"
	hashedrekord_v001 "github.com/sigstore/rekor/pkg/types/hashedrekord/v0.0.1"
	intoto_v001 "github.com/sigstore/rekor/pkg/types/intoto/v0.0.1"
	intoto_v002 "github.com/sigstore/rekor/pkg/types/intoto/v0.0.2"
	rekord_v001 "github.com/sigstore/rekor/pkg/types/rekord/v0.0.1"
)

// verifyWithCosign verifies attestations attached to an image reference
func verifyWithCosign(ctx context.Context, ref name.Reference, cfg *registryauth.Config) ([]VerifiedAttestation, error) {
	statements, err := verifyWithCosignStatements(ctx, ref, cfg)
	if err != nil {
		return nil, err
	}

	results := make([]VerifiedAttestation, 0, len(statements))
	for _, statement := range statements {
		results = append(results, statement.Attestation)
	}

	return results, nil
}

func verifyWithCosignStatements(ctx context.Context, ref name.Reference, cfg *registryauth.Config) ([]VerifiedStatement, error) {
	// resolve registry authentication
	keychain, _, err := registryauth.KeyChainForImage(cfg, ref.Name())

	if err != nil {
		return nil, fmt.Errorf("image keychain error : %w", err)
	}

	// Load Fulcio root certificates (this is what cosign CLI does implicitly)
	roots, err := fulcio.GetRoots()
	if err != nil {
		return nil, fmt.Errorf("load fulcio roots: %w", err)
	}
	intermediates, err := fulcio.GetIntermediates()
	if err != nil {
		return nil, fmt.Errorf("load fulcio intermediates: %w", err)
	}
	rekorClient, err := newRekorClient(cosignoptions.DefaultRekorURL)
	if err != nil {
		return nil, fmt.Errorf("create Rekor client: %w", err)
	}
	opts := &cosign.CheckOpts{
		RootCerts:         roots,
		IntermediateCerts: intermediates,
		RekorClient:       rekorClient,
		RegistryClientOpts: []ociremote.Option{
			ociremote.WithRemoteOptions(
				remote.WithAuthFromKeychain(keychain),
			),
		},
	}

	checked, _, err := cosign.VerifyImageAttestations(ctx, ref, opts)

	if err != nil {
		if isBundleCompatibilityError(err) {
			compatChecked, compatErr := verifyWithBundleCompatibilityStatements(ctx, ref, cfg)
			if compatErr == nil && len(compatChecked) > 0 {
				return compatChecked, nil
			}
		}
		return nil, fmt.Errorf("verify attestations: %w", err)
	}
	if len(checked) == 0 {
		return nil, fmt.Errorf("no verified attestations found")
	}
	results := make([]VerifiedStatement, 0, len(checked))

	for _, sig := range checked {
		cert, _ := sig.Cert() // cert may be nil for some verification modes

		subject, issuer := certSubjectIssuer(cert)
		statement, err := decodeStatement(sig)
		if err != nil {
			return nil, err
		}
		bundle, _ := sig.Bundle()

		results = append(results, VerifiedStatement{
			Attestation: VerifiedAttestation{
				Subject:           subject,
				Issuer:            issuer,
				RekorEntryPresent: bundle != nil,
				ImageDigest:       subjectDigest(statement.Subject),
				PredicateType:     statement.PredicateType,
				SourceRepo:        extractSourceRepo(predicateMap(statement.Predicate)),
				BuilderID:         extractBuilderID(predicateMap(statement.Predicate)),
				WorkflowRef:       extractWorkflowRef(predicateMap(statement.Predicate)),
			},
			Statement: statement,
		})
	}
	return results, nil
}

func discoverWithCosign(ctx context.Context, ref name.Reference, cfg *registryauth.Config) ([]VerifiedAttestation, error) {
	layers, err := discoverSignatureLayers(ctx, ref, cfg)
	if err != nil {
		return nil, err
	}
	if len(layers) == 0 {
		return nil, nil
	}

	results := make([]VerifiedAttestation, 0, len(layers))
	for _, sig := range layers {
		cert, _ := sig.Cert()
		subject, issuer := certSubjectIssuer(cert)
		statement, _ := decodeStatement(sig)
		bundle, _ := sig.Bundle()

		discovered := VerifiedAttestation{
			Subject:           subject,
			Issuer:            issuer,
			RekorEntryPresent: bundle != nil,
		}

		if statement != nil {
			predicate := predicateMap(statement.Predicate)
			discovered.ImageDigest = subjectDigest(statement.Subject)
			discovered.PredicateType = statement.PredicateType
			discovered.SourceRepo = extractSourceRepo(predicate)
			discovered.BuilderID = extractBuilderID(predicate)
			discovered.WorkflowRef = extractWorkflowRef(predicate)
		}

		results = append(results, discovered)
	}

	return results, nil
}

func discoverSignatureLayers(ctx context.Context, ref name.Reference, cfg *registryauth.Config) ([]oci.Signature, error) {
	keychain, _, err := registryauth.KeyChainForImage(cfg, ref.Name())
	if err != nil {
		return nil, fmt.Errorf("image keychain error : %w", err)
	}

	opts := []ociremote.Option{
		ociremote.WithRemoteOptions(
			remote.WithContext(ctx),
			remote.WithAuthFromKeychain(keychain),
		),
	}

	entity, err := ociremote.SignedEntity(ref, opts...)
	if err != nil {
		return nil, fmt.Errorf("discover attestations: %w", err)
	}

	atts, err := entity.Attestations()
	if err != nil {
		return nil, fmt.Errorf("discover attestations: %w", err)
	}

	layers, err := atts.Get()
	if err != nil {
		return nil, fmt.Errorf("discover attestations: %w", err)
	}
	if len(layers) == 0 {
		return nil, nil
	}

	return layers, nil
}

func certSubjectIssuer(cert *x509.Certificate) (subject, issuer string) {
	if cert == nil {
		return "", ""
	}

	return cert.Subject.String(), cert.Issuer.String()
}

type dsseEnvelope struct {
	Payload string `json:"payload"`
}

func decodeStatement(sig oci.Signature) (*in_toto.Statement, error) {
	payload, err := sig.Payload()
	if err != nil {
		return nil, fmt.Errorf("read attestation payload: %w", err)
	}

	var env dsseEnvelope
	if err := json.Unmarshal(payload, &env); err != nil {
		return nil, fmt.Errorf("decode DSSE envelope: %w", err)
	}

	decoded, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return nil, fmt.Errorf("decode DSSE payload: %w", err)
	}

	var statement in_toto.Statement
	if err := json.Unmarshal(decoded, &statement); err != nil {
		return nil, fmt.Errorf("decode in-toto statement: %w", err)
	}

	return &statement, nil
}

func subjectDigest(subjects []in_toto.Subject) string {
	for _, subject := range subjects {
		for algo, digest := range subject.Digest {
			if digest == "" {
				continue
			}
			if algo == "" {
				return digest
			}
			return algo + ":" + digest
		}
	}

	return ""
}

func extractSourceRepo(predicate map[string]interface{}) string {
	return firstNonEmpty(
		stringAt(predicate, "invocation", "configSource", "uri"),
		stringAt(predicate, "buildDefinition", "externalParameters", "workflow", "repository"),
		firstURIFromList(mapSliceAt(predicate, "materials")),
		firstURIFromList(mapSliceAt(predicate, "buildDefinition", "resolvedDependencies")),
	)
}

func extractBuilderID(predicate map[string]interface{}) string {
	return firstNonEmpty(
		stringAt(predicate, "builder", "id"),
		stringAt(predicate, "runDetails", "builder", "id"),
	)
}

func extractWorkflowRef(predicate map[string]interface{}) string {
	repo := stringAt(predicate, "buildDefinition", "externalParameters", "workflow", "repository")
	ref := stringAt(predicate, "buildDefinition", "externalParameters", "workflow", "ref")
	path := stringAt(predicate, "buildDefinition", "externalParameters", "workflow", "path")

	var parts []string
	for _, part := range []string{repo, ref, path} {
		if part != "" {
			parts = append(parts, part)
		}
	}

	if len(parts) == 0 {
		return ""
	}

	return strings.Join(parts, "@")
}

func firstURIFromList(items []map[string]interface{}) string {
	for _, item := range items {
		uri := stringAt(item, "uri")
		if uri != "" {
			return uri
		}
	}

	return ""
}

func stringAt(root map[string]interface{}, path ...string) string {
	current := any(root)
	for _, part := range path {
		node, ok := current.(map[string]interface{})
		if !ok {
			return ""
		}
		current, ok = node[part]
		if !ok {
			return ""
		}
	}

	value, _ := current.(string)
	return value
}

func mapSliceAt(root map[string]interface{}, path ...string) []map[string]interface{} {
	current := any(root)
	for _, part := range path {
		node, ok := current.(map[string]interface{})
		if !ok {
			return nil
		}
		current, ok = node[part]
		if !ok {
			return nil
		}
	}

	items, ok := current.([]interface{})
	if !ok {
		return nil
	}

	result := make([]map[string]interface{}, 0, len(items))
	for _, item := range items {
		if m, ok := item.(map[string]interface{}); ok {
			result = append(result, m)
		}
	}

	return result
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}

	return ""
}

func predicateMap(predicate interface{}) map[string]interface{} {
	m, _ := predicate.(map[string]interface{})
	return m
}

func verifyWithBundleCompatibilityStatements(ctx context.Context, ref name.Reference, cfg *registryauth.Config) ([]VerifiedStatement, error) {
	layers, err := discoverSignatureLayers(ctx, ref, cfg)
	if err != nil {
		return nil, err
	}
	if len(layers) == 0 {
		return nil, nil
	}

	results := make([]VerifiedStatement, 0, len(layers))
	for _, sig := range layers {
		if err := verifyCompatibleBundle(ctx, sig); err != nil {
			return nil, err
		}

		cert, _ := sig.Cert()
		subject, issuer := certSubjectIssuer(cert)
		statement, err := decodeStatement(sig)
		if err != nil {
			return nil, err
		}
		bundle, _ := sig.Bundle()

		results = append(results, VerifiedStatement{
			Attestation: VerifiedAttestation{
				Subject:           subject,
				Issuer:            issuer,
				RekorEntryPresent: bundle != nil,
				ImageDigest:       subjectDigest(statement.Subject),
				PredicateType:     statement.PredicateType,
				SourceRepo:        extractSourceRepo(predicateMap(statement.Predicate)),
				BuilderID:         extractBuilderID(predicateMap(statement.Predicate)),
				WorkflowRef:       extractWorkflowRef(predicateMap(statement.Predicate)),
			},
			Statement: statement,
		})
	}

	return results, nil
}

func isBundleCompatibilityError(err error) bool {
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "invalid kind value") ||
		strings.Contains(msg, "signature not found in transparency log") ||
		strings.Contains(msg, "matching bundle to payload")
}

func verifyCompatibleBundle(ctx context.Context, sig oci.Signature) error {
	bundle, err := sig.Bundle()
	if err != nil {
		return err
	}
	if bundle == nil {
		return errors.New("missing rekor bundle")
	}

	publicKeys, err := cosign.GetRekorPubs(ctx, nil)
	if err != nil {
		return fmt.Errorf("retrieving rekor public key: %w", err)
	}

	pubKey, ok := publicKeys[bundle.Payload.LogID]
	if !ok {
		return fmt.Errorf("rekor log public key not found for payload")
	}

	if err := cosign.VerifySET(bundle.Payload, bundle.SignedEntryTimestamp, pubKey.PubKey); err != nil {
		return err
	}

	payload, err := sig.Payload()
	if err != nil {
		return fmt.Errorf("reading payload: %w", err)
	}
	signature, err := sig.Base64Signature()
	if err != nil {
		return fmt.Errorf("reading base64signature: %w", err)
	}

	alg, bundleHash, err := compatibleBundleHash(bundle.Payload.Body.(string), signature)
	if err != nil {
		return fmt.Errorf("computing bundle hash: %w", err)
	}
	if alg != "sha256" {
		return fmt.Errorf("unexpected bundle algorithm %q", alg)
	}
	if bundleHash != sha256Hex(payload) {
		return fmt.Errorf("bundle hash mismatch")
	}

	return nil
}

func compatibleBundleHash(bundleBody, _ string) (string, string, error) {
	entryImpl, err := extractEntryImpl(bundleBody)
	if err != nil {
		return "", "", err
	}

	switch entry := entryImpl.(type) {
	case *dsse_v001.V001Entry:
		return *entry.DSSEObj.EnvelopeHash.Algorithm, *entry.DSSEObj.EnvelopeHash.Value, nil
	case *hashedrekord_v001.V001Entry:
		return *entry.HashedRekordObj.Data.Hash.Algorithm, *entry.HashedRekordObj.Data.Hash.Value, nil
	case *intoto_v001.V001Entry:
		return *entry.IntotoObj.Content.Hash.Algorithm, *entry.IntotoObj.Content.Hash.Value, nil
	case *intoto_v002.V002Entry:
		return *entry.IntotoObj.Content.Hash.Algorithm, *entry.IntotoObj.Content.Hash.Value, nil
	case *rekord_v001.V001Entry:
		return *entry.RekordObj.Data.Hash.Algorithm, *entry.RekordObj.Data.Hash.Value, nil
	default:
		return "", "", errors.New("unsupported bundle entry type")
	}
}

func extractEntryImpl(bundleBody string) (rekortypes.EntryImpl, error) {
	entry, err := rekormodels.UnmarshalProposedEntry(
		base64.NewDecoder(base64.StdEncoding, strings.NewReader(bundleBody)),
		runtime.JSONConsumer(),
	)
	if err != nil {
		return nil, err
	}

	return rekortypes.UnmarshalEntry(entry)
}

func sha256Hex(payload []byte) string {
	sum := sha256.Sum256(payload)
	return fmt.Sprintf("%x", sum[:])
}

func newRekorClient(rekorURL string) (*generatedclient.Rekor, error) {
	rekorClient, err := cosignrekor.NewClient(rekorURL)
	if err != nil {
		return nil, err
	}

	// go-openapi treats any non-empty DEBUG environment variable as "dump all HTTP
	// requests/responses". This environment commonly sets DEBUG=release, which is
	// fine for app logging but causes very noisy Rekor wire dumps during corpus runs.
	if rt, ok := rekorClient.Transport.(*httptransport.Runtime); ok {
		rt.SetDebug(false)
	}

	return rekorClient, nil
}
