// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//go:build s3experiment

package delivery

import (
	e "github.com/dsx-ai-factory/nvkr/pkg/nvkr/errors"
	"testing"
)

func TestExperimentalEndpointAdmission(t *testing.T) {
	for _, endpoint := range []string{"https://127.0.0.1:9000", "http://localhost:9000", "http://example.com:9000", "http://127.0.0.1:0", "http://127.0.0.1:65536", "http://127.0.0.1:9000/path", "http://user:pass@127.0.0.1:9000", "http://127.0.0.1:9000?", "http://127.0.0.1:9000#fragment"} {
		t.Run(endpoint, func(t *testing.T) {
			store, err := NewExperimentalLocalObjectStore(t.Context(), endpoint)
			requireObjectCode(t, err, e.CodeUsage)
			if store != nil {
				t.Fatal("unsupported endpoint admitted a store")
			}
		})
	}
	store, err := NewExperimentalLocalObjectStore(t.Context(), "http://127.0.0.1:9000")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
}
