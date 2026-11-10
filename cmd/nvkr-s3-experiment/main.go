// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//go:build s3experiment

// Command nvkr-s3-experiment is an opt-in local transport experiment.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"time"

	e "github.com/dsx-ai-factory/nvkr/pkg/nvkr/errors"
	"github.com/dsx-ai-factory/nvkr/pkg/nvkr/s3experiment"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	if err := run(ctx); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(e.ExitCode(err))
	}
}

func run(ctx context.Context) error {
	mode := flag.String("mode", "", "publish, verify, or tamper")
	endpoint := flag.String("endpoint", "", "literal loopback S3 HTTP origin")
	repository := flag.String("repository", "", "loopback OCI repository (publish)")
	artifact := flag.String("artifact", "", "built nvkr binary (publish)")
	state := flag.String("state", "", "directory for release.ref and independently trusted local public key")
	flag.Parse()
	if *state == "" || flag.NArg() != 0 {
		return e.New(e.CodeUsage, "state directory is required; no positional arguments")
	}
	if *mode == "publish" {
		if err := os.MkdirAll(*state, 0700); err != nil {
			return e.Wrap(e.CodeUsage, err, "creating state directory")
		}
		ref, pub, err := s3experiment.Publish(ctx, *endpoint, *repository, *artifact)
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(*state, "trusted-local-key.pub"), pub, 0600); err != nil {
			return e.Wrap(e.CodeUnavailable, err, "writing public trust anchor")
		}
		if err := os.WriteFile(filepath.Join(*state, "release.ref"), []byte(ref+"\n"), 0600); err != nil {
			return e.Wrap(e.CodeUnavailable, err, "writing immutable release reference")
		}
		fmt.Println("Published experimental OCI release:", ref)
		return s3experiment.Describe(ctx, *endpoint, ref, os.Stdout)
	}
	if *mode != "verify" && *mode != "tamper" {
		return e.New(e.CodeUsage, "mode must be publish, verify, or tamper")
	}
	ref, err := os.ReadFile(filepath.Join(*state, "release.ref"))
	if err != nil {
		return e.Wrap(e.CodeUsage, err, "reading release reference")
	}
	pub, err := os.ReadFile(filepath.Join(*state, "trusted-local-key.pub"))
	if err != nil {
		return e.Wrap(e.CodeUsage, err, "reading independent local trust anchor")
	}
	if *mode == "tamper" {
		if err := s3experiment.Tamper(ctx, *endpoint, strings.TrimSpace(string(ref)), pub); err != nil {
			return err
		}
		fmt.Println("Tampered S3 artifact with same-size corruption")
		return nil
	}
	files, err := s3experiment.Verify(ctx, *endpoint, strings.TrimSpace(string(ref)), pub)
	if err != nil {
		return err
	}
	output := filepath.Join(*state, "downloaded")
	if err := os.Mkdir(output, 0700); err != nil {
		return e.Wrap(e.CodeUsage, err, "creating fresh download directory")
	}
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if err := os.WriteFile(filepath.Join(output, name), files[name], 0600); err != nil {
			return e.Wrap(e.CodeUnavailable, err, "saving verified file")
		}
		fmt.Printf("Verified and downloaded %s (%d bytes)\n", name, len(files[name]))
	}
	fmt.Println("VERIFY OK: OCI digest, independent local key, S3 SHA256/size, and checksum sidecar match")
	return nil
}
