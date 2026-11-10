// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//go:build s3experiment

package s3experiment

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/dsx-ai-factory/nvkr/pkg/nvkr/canonical"
	"github.com/dsx-ai-factory/nvkr/pkg/nvkr/delivery"
	e "github.com/dsx-ai-factory/nvkr/pkg/nvkr/errors"
)

type memoryStore map[string][]byte

func (s memoryStore) PutIfAbsent(_ context.Context, object delivery.Object, reader io.ReadSeeker) (delivery.StoredObject, error) {
	raw, err := io.ReadAll(reader)
	if err != nil {
		return delivery.StoredObject{}, err
	}
	s[object.Key] = raw
	return delivery.StoredObject{Object: object, ETag: `"fixture"`}, nil
}
func (s memoryStore) OpenPinned(_ context.Context, object delivery.StoredObject) (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(s[object.Key])), nil
}
func (s memoryStore) Close() error { return nil }

func TestVerifyRecord(t *testing.T) {
	for _, scenario := range []string{"valid", "same size corruption", "truncated", "missing SBOM", "wrong trust key", "changed destination", "changed key", "missing member", "bad checksum", "wrong media type", "unknown schema", "signature corruption"} {
		t.Run(scenario, func(t *testing.T) {
			store := memoryStore{}
			pub, private, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			artifact := []byte("real-test-bytes")
			checksum := []byte(strings.TrimPrefix(blobDigest(artifact), "sha256:") + "  nvkr\n")
			if scenario == "bad checksum" {
				checksum[0] ^= 1
			}
			record := Record{Payload: Payload{Schema: schema, Lane: "static-unqualified", Endpoint: "http://127.0.0.1:9000", Bucket: Bucket, Prefix: Prefix}}
			for i, raw := range [][]byte{artifact, checksum, []byte(`{"local":"observation"}`), []byte(`{"bomFormat":"CycloneDX"}`)} {
				object, err := put(t.Context(), store, raw, []string{"application/octet-stream", "text/plain", "application/vnd.in-toto+json", "application/vnd.cyclonedx+json"}[i])
				if err != nil {
					t.Fatal(err)
				}
				record.Payload.Files = append(record.Payload.Files, File{Name: []string{"nvkr", "nvkr.sha256", "provenance.json", "sbom.cdx.json"}[i], Object: object})
			}
			raw, err := canonical.Marshal(record.Payload)
			if err != nil {
				t.Fatal(err)
			}
			record.Signature, err = put(t.Context(), store, ed25519.Sign(private, raw), "application/octet-stream")
			if err != nil {
				t.Fatal(err)
			}
			want := e.CodeVerifyFailed
			switch scenario {
			case "same size corruption":
				store[record.Payload.Files[0].Object.Key][0] ^= 1
			case "truncated":
				store[record.Payload.Files[0].Object.Key] = []byte("short")
			case "missing SBOM":
				delete(store, record.Payload.Files[3].Object.Key)
			case "wrong trust key":
				pub[0] ^= 1
				want = e.CodeUntrustedSigner
			case "changed destination":
				record.Payload.Endpoint = "http://127.0.0.1:9001"
				want = e.CodeUntrustedSigner
			case "changed key":
				record.Payload.Files[0].Object.Key = "other"
			case "missing member":
				record.Payload.Files = record.Payload.Files[:3]
			case "wrong media type":
				record.Payload.Files[0].Object.MediaType = "text/plain"
			case "unknown schema":
				record.Payload.Schema = "unknown"
			case "signature corruption":
				store[record.Signature.Key][0] ^= 1
			}
			files, err := verifyRecord(t.Context(), store, record, pub)
			if scenario == "valid" {
				if err != nil || !bytes.Equal(files["nvkr"], artifact) {
					t.Fatalf("valid round trip: %v", err)
				}
				return
			}
			var coded *e.Error
			if !errors.As(err, &coded) || coded.Code != want || files != nil {
				t.Fatalf("got %v, want %s without files", err, want)
			}
		})
	}
}
