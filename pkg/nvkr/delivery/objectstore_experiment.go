// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//go:build s3experiment

package delivery

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	e "github.com/dsx-ai-factory/nvkr/pkg/nvkr/errors"
)

// ExperimentalLocalEndpoint admits only literal IPv4 loopback HTTP origins.
// This opt-in build-tagged experiment never changes production S3 admission.
func ExperimentalLocalEndpoint(endpoint string) error {
	u, err := url.Parse(endpoint)
	if err != nil {
		return e.New(e.CodeUsage, "experiment requires http://127.0.0.1:<port>")
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil || port < 1 || port > 65535 || u.Scheme != "http" || u.Hostname() != "127.0.0.1" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.ForceQuery {
		return e.New(e.CodeUsage, "experiment requires http://127.0.0.1:<port>")
	}
	return nil
}

// NewExperimentalLocalObjectStore reuses the production conditional PUT,
// multipart, pinned GET and cleanup implementation with a loopback-only client.
// Its fixed credentials are public test values. It grants no release authority.
// Only the explicit s3experiment build contains this constructor.
func NewExperimentalLocalObjectStore(ctx context.Context, endpoint string) (ObjectStore, error) {
	if err := ExperimentalLocalEndpoint(endpoint); err != nil {
		return nil, err
	}
	if err := deliveryContext(ctx); err != nil {
		return nil, err
	}
	lifetime, cancel := context.WithTimeout(ctx, 5*time.Minute)
	transport := &http.Transport{ResponseHeaderTimeout: 15 * time.Second}
	client := &http.Client{Transport: transport, Timeout: 5 * time.Minute, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	store := &s3ObjectStore{
		options:  S3ObjectStoreOptions{Region: "us-east-1", Bucket: "nvkr-experiment", Prefix: "artifacts", ExpectedBucketOwner: "000000000000", PartSizeBytes: 8 << 20, OperationTimeout: 5 * time.Minute, CleanupTimeout: 10 * time.Second, MaxAttempts: 1, MaxUploadAttempts: 2},
		lifetime: lifetime, cancel: cancel, transport: transport, bodies: make(map[*objectResponseBody]struct{}),
	}
	store.api = s3.New(s3.Options{Region: "us-east-1", BaseEndpoint: aws.String(endpoint), UsePathStyle: true,
		Credentials: credentials.NewStaticCredentialsProvider("nvkr-local-test", "nvkr-local-test-secret", ""), HTTPClient: client,
		RetryMaxAttempts: 1, RequestChecksumCalculation: aws.RequestChecksumCalculationWhenRequired, ResponseChecksumValidation: aws.ResponseChecksumValidationWhenRequired})
	return store, nil
}
