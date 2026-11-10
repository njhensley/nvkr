// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//go:build s3experiment

// Package s3experiment is a local transport experiment, not a production Release
// issuer. It joins the existing S3 ObjectStore and OCI document transport without
// bypassing or extending production lifecycle admission. Its locally signed
// records cannot be accepted by nvkr release verify.
package s3experiment

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/dsx-ai-factory/nvkr/pkg/nvkr/canonical"
	"github.com/dsx-ai-factory/nvkr/pkg/nvkr/delivery"
	e "github.com/dsx-ai-factory/nvkr/pkg/nvkr/errors"
)

const (
	mediaType = "application/vnd.nvkr.experimental.s3-release.v1+json"
	schema    = "nvkr.dev/experimental-local-s3-release/v1"
	maxBlob   = 128 << 20
	maxRecord = 1 << 20
	Bucket    = "nvkr-experiment"
	Prefix    = "artifacts"
)

var registry = delivery.RegistryOptions{PlainHTTP: true, Anonymous: true}

type File struct {
	Name   string                `json:"name"`
	Object delivery.StoredObject `json:"object"`
}

type Payload struct {
	Schema   string `json:"schema"`
	Lane     string `json:"lane"`
	Endpoint string `json:"endpoint"`
	Bucket   string `json:"bucket"`
	Prefix   string `json:"prefix"`
	Files    []File `json:"files"`
}

type Record struct {
	Payload   Payload               `json:"payload"`
	Signature delivery.StoredObject `json:"signature"`
}

// Publish uploads the built binary, its actual Go module inventory, checksum and
// local observation provenance through the existing NVKR S3 transport. It then
// publishes a digest-addressed OCI record containing exact S3 locators. The
// ephemeral private signing key is never persisted. The returned public key must
// be supplied independently by the consumer; a key from the record is not trust.
func Publish(ctx context.Context, endpoint, repository, artifact string) (reference string, publicKey []byte, resultErr error) {
	if err := admit(endpoint, repository, false); err != nil {
		return "", nil, err
	}
	raw, err := readFile(ctx, artifact)
	if err != nil {
		return "", nil, err
	}
	info, err := buildinfo.Read(bytes.NewReader(raw))
	if err != nil {
		return "", nil, e.Wrap(e.CodeVerifyFailed, err, "artifact must be a real Go binary")
	}
	components := []map[string]any{}
	for _, dep := range info.Deps {
		if dep.Replace != nil {
			dep = dep.Replace
		}
		components = append(components, map[string]any{"type": "library", "name": dep.Path, "version": dep.Version})
	}
	sort.Slice(components, func(i, j int) bool { return components[i]["name"].(string) < components[j]["name"].(string) })
	sbom, err := canonical.Marshal(map[string]any{"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
		"metadata": map[string]any{"component": map[string]any{"type": "application", "name": "nvkr", "hashes": []any{map[string]any{"alg": "SHA-256", "content": strings.TrimPrefix(blobDigest(raw), "sha256:")}}}}, "components": components})
	if err != nil {
		return "", nil, err
	}
	provenance, err := canonical.Marshal(map[string]any{"_type": "https://in-toto.io/Statement/v1", "predicateType": "https://nvkr.dev/experimental/local-observation/v1",
		"subject":   []any{map[string]any{"name": "nvkr", "digest": map[string]string{"sha256": strings.TrimPrefix(blobDigest(raw), "sha256:")}}},
		"predicate": map[string]any{"scope": "local build observation; no isolated Run or SLSA level claim", "goVersion": info.GoVersion, "buildSettings": info.Settings, "module": info.Main}})
	if err != nil {
		return "", nil, err
	}
	store, err := delivery.NewExperimentalLocalObjectStore(ctx, endpoint)
	if err != nil {
		return "", nil, err
	}
	defer func() {
		resultErr = errors.Join(resultErr, store.Close())
		if resultErr != nil {
			reference, publicKey = "", nil
		}
	}()
	payload := Payload{Schema: schema, Lane: "static-unqualified", Endpoint: endpoint, Bucket: Bucket, Prefix: Prefix}
	inputs := []struct {
		name, media string
		raw         []byte
	}{
		{"nvkr", "application/octet-stream", raw},
		{"nvkr.sha256", "text/plain", []byte(strings.TrimPrefix(blobDigest(raw), "sha256:") + "  nvkr\n")},
		{"provenance.json", "application/vnd.in-toto+json", provenance},
		{"sbom.cdx.json", "application/vnd.cyclonedx+json", sbom},
	}
	for _, input := range inputs {
		object, err := put(ctx, store, input.raw, input.media)
		if err != nil {
			return "", nil, err
		}
		payload.Files = append(payload.Files, File{Name: input.name, Object: object})
	}
	pub, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", nil, e.Wrap(e.CodeInternal, err, "creating local signing key")
	}
	signed, err := canonical.Marshal(payload)
	if err != nil {
		return "", nil, err
	}
	sig, err := put(ctx, store, ed25519.Sign(private, signed), "application/octet-stream")
	if err != nil {
		return "", nil, err
	}
	document, err := canonical.Marshal(Record{Payload: payload, Signature: sig})
	if err != nil {
		return "", nil, err
	}
	ref, err := delivery.PushDocumentArtifact(ctx, repository, mediaType, document, registry)
	if err != nil {
		return "", nil, err
	}
	return ref, pub, nil
}

func put(ctx context.Context, store delivery.ObjectStore, raw []byte, media string) (delivery.StoredObject, error) {
	digest := blobDigest(raw)
	object := delivery.Object{Key: "blobs/sha256/" + strings.TrimPrefix(digest, "sha256:"), SHA256: digest, Size: int64(len(raw)), MediaType: media}
	stored, err := store.PutIfAbsent(ctx, object, bytes.NewReader(raw))
	if err != nil {
		return delivery.StoredObject{}, err
	}
	if _, err := readObject(ctx, store, stored); err != nil {
		return delivery.StoredObject{}, err
	}
	return stored, nil
}

// Verify starts at the immutable OCI record. It authenticates the local signature
// under the independently supplied key, then downloads and checks every S3 file.
// This checks transport integrity and a local signature, not NVKR Release policy.
func Verify(ctx context.Context, endpoint, reference string, trustedKey []byte) (files map[string][]byte, resultErr error) {
	record, err := fetchRecord(ctx, endpoint, reference)
	if err != nil {
		return nil, err
	}
	store, err := delivery.NewExperimentalLocalObjectStore(ctx, endpoint)
	if err != nil {
		return nil, err
	}
	defer func() {
		resultErr = errors.Join(resultErr, store.Close())
		if resultErr != nil {
			files = nil
		}
	}()
	return verifyRecord(ctx, store, record, trustedKey)
}

func verifyRecord(ctx context.Context, store delivery.ObjectStore, record Record, trustedKey []byte) (map[string][]byte, error) {
	if err := validateRecord(record); err != nil {
		return nil, err
	}
	signed, err := canonical.Marshal(record.Payload)
	if err != nil {
		return nil, err
	}
	sig, err := readObject(ctx, store, record.Signature)
	if err != nil {
		return nil, err
	}
	if len(trustedKey) != ed25519.PublicKeySize || !ed25519.Verify(ed25519.PublicKey(trustedKey), signed, sig) {
		return nil, e.New(e.CodeUntrustedSigner, "experimental release signature does not match trusted local key")
	}
	files := make(map[string][]byte)
	for _, file := range record.Payload.Files {
		raw, err := readObject(ctx, store, file.Object)
		if err != nil {
			return nil, e.Wrap(e.CodeVerifyFailed, err, "S3 verification failed for %s", file.Name)
		}
		files[file.Name] = raw
	}
	if string(files["nvkr.sha256"]) != strings.TrimPrefix(blobDigest(files["nvkr"]), "sha256:")+"  nvkr\n" {
		return nil, e.New(e.CodeVerifyFailed, "checksum sidecar differs from artifact")
	}
	return files, nil
}

func fetchRecord(ctx context.Context, endpoint, reference string) (Record, error) {
	if err := admit(endpoint, reference, true); err != nil {
		return Record{}, err
	}
	raw, err := delivery.PullDocumentArtifact(ctx, reference, mediaType, maxRecord, registry)
	if err != nil {
		return Record{}, err
	}
	var record Record
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil {
		return Record{}, e.Wrap(e.CodeVerifyFailed, err, "decoding experimental release")
	}
	canonicalBytes, err := canonical.Marshal(record)
	if err != nil || !bytes.Equal(raw, canonicalBytes) {
		return Record{}, e.New(e.CodeVerifyFailed, "release record must be exact canonical bytes")
	}
	if record.Payload.Endpoint != endpoint {
		return Record{}, e.New(e.CodeVerifyFailed, "release endpoint differs from admitted local target")
	}
	if err := validateRecord(record); err != nil {
		return Record{}, err
	}
	return record, nil
}

func validateRecord(record Record) error {
	p := record.Payload
	if p.Schema != schema || p.Lane != "static-unqualified" || p.Bucket != Bucket || p.Prefix != Prefix || len(p.Files) != 4 {
		return e.New(e.CodeVerifyFailed, "invalid experimental release schema, lane, destination or membership")
	}
	if err := delivery.ExperimentalLocalEndpoint(p.Endpoint); err != nil {
		return err
	}
	names := []string{"nvkr", "nvkr.sha256", "provenance.json", "sbom.cdx.json"}
	media := []string{"application/octet-stream", "text/plain", "application/vnd.in-toto+json", "application/vnd.cyclonedx+json"}
	for i, file := range p.Files {
		if file.Name != names[i] || file.Object.MediaType != media[i] {
			return e.New(e.CodeVerifyFailed, "release file membership or media type differs")
		}
		if err := validateObject(file.Object); err != nil {
			return err
		}
	}
	if record.Signature.Size != ed25519.SignatureSize || record.Signature.MediaType != "application/octet-stream" {
		return e.New(e.CodeVerifyFailed, "invalid signature object")
	}
	return validateObject(record.Signature)
}

func validateObject(object delivery.StoredObject) error {
	if !canonical.IsDigest(object.SHA256) || object.Key != "blobs/sha256/"+strings.TrimPrefix(object.SHA256, "sha256:") || object.Size <= 0 || object.Size > maxBlob || (object.ETag == "" && object.VersionID == "") {
		return e.New(e.CodeVerifyFailed, "invalid digest-addressed S3 locator")
	}
	return nil
}

func readObject(ctx context.Context, store delivery.ObjectStore, object delivery.StoredObject) ([]byte, error) {
	if err := validateObject(object); err != nil {
		return nil, err
	}
	body, err := store.OpenPinned(ctx, object)
	if err != nil {
		return nil, err
	}
	raw, readErr := io.ReadAll(io.LimitReader(body, object.Size+1))
	if err := errors.Join(readErr, body.Close()); err != nil {
		return nil, e.Wrap(e.CodeVerifyFailed, err, "reading S3 object")
	}
	if int64(len(raw)) != object.Size || blobDigest(raw) != object.SHA256 {
		return nil, e.New(e.CodeVerifyFailed, "S3 object SHA256 or size differs from OCI record")
	}
	if err := ctx.Err(); err != nil {
		return nil, e.Wrap(e.CodeTimeout, err, "reading S3 object")
	}
	return raw, nil
}

func blobDigest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func readFile(ctx context.Context, path string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, e.Wrap(e.CodeTimeout, err, "reading artifact")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, e.Wrap(e.CodeUsage, err, "opening built artifact")
	}
	raw, readErr := io.ReadAll(io.LimitReader(f, maxBlob+1))
	if err := errors.Join(readErr, f.Close()); err != nil {
		return nil, e.Wrap(e.CodeUsage, err, "reading artifact")
	}
	if len(raw) == 0 || len(raw) > maxBlob {
		return nil, e.New(e.CodeUsage, "artifact must be nonempty and at most 128 MiB")
	}
	return raw, nil
}

func admit(endpoint, reference string, pinned bool) error {
	if err := delivery.ExperimentalLocalEndpoint(endpoint); err != nil {
		return err
	}
	parts := strings.SplitN(reference, "/", 2)
	if len(parts) != 2 || parts[1] == "" {
		return e.New(e.CodeUsage, "experiment requires a loopback OCI repository")
	}
	if err := delivery.ExperimentalLocalEndpoint("http://" + parts[0]); err != nil {
		return err
	}
	if pinned && !strings.Contains(reference, "@sha256:") {
		return e.New(e.CodeUnpinnedSource, "verification requires immutable OCI digest")
	}
	return nil
}

// Tamper deliberately overwrites only this experiment's artifact object, using
// the fixed local credentials. It is separate from the immutable ObjectStore API.
// Same-size corruption exercises either the pinned validator or full digest gate.
func Tamper(ctx context.Context, endpoint, reference string, trustedKey []byte) error {
	files, err := Verify(ctx, endpoint, reference, trustedKey)
	if err != nil {
		return err
	}
	raw := files["nvkr"]
	key := Prefix + "/blobs/sha256/" + strings.TrimPrefix(blobDigest(raw), "sha256:")
	raw[0] ^= 1
	transport := &http.Transport{ResponseHeaderTimeout: 15 * time.Second}
	defer transport.CloseIdleConnections()
	client := s3.New(s3.Options{Region: "us-east-1", BaseEndpoint: aws.String(endpoint), UsePathStyle: true,
		Credentials:      credentials.NewStaticCredentialsProvider("nvkr-local-test", "nvkr-local-test-secret", ""),
		HTTPClient:       &http.Client{Transport: transport, Timeout: time.Minute, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		RetryMaxAttempts: 1, RequestChecksumCalculation: aws.RequestChecksumCalculationWhenRequired})
	_, err = client.PutObject(ctx, &s3.PutObjectInput{Bucket: aws.String(Bucket), Key: aws.String(key), Body: bytes.NewReader(raw), ContentLength: aws.Int64(int64(len(raw))), ContentType: aws.String("application/octet-stream")})
	if err != nil {
		return e.Wrap(e.CodeUnavailable, err, "overwriting local experiment object")
	}
	return nil
}

// Describe prints exact physical S3 keys carried by the OCI record for the run log.
func Describe(ctx context.Context, endpoint, reference string, out io.Writer) error {
	record, err := fetchRecord(ctx, endpoint, reference)
	if err != nil {
		return err
	}
	for _, file := range append(record.Payload.Files, File{Name: "release.ed25519", Object: record.Signature}) {
		if _, err := fmt.Fprintf(out, "%s s3://%s/%s/%s %s size=%d mediaType=%s\n", file.Name, Bucket, Prefix, file.Object.Key, file.Object.SHA256, file.Object.Size, file.Object.MediaType); err != nil {
			return e.Wrap(e.CodeUnavailable, err, "printing object locator")
		}
	}
	return nil
}
