// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package factory

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/dsx-ai-factory/nvkr/internal/ownedcmd"
	e "github.com/dsx-ai-factory/nvkr/pkg/nvkr/errors"
)

// Compile a separate command that imports only the public serving API. This
// proves the pilot's executable boundary independently of test-binary re-entry.
func TestTektonProjectionCompiledAdapterEquivalence(t *testing.T) {
	if testing.Short() {
		t.Skip("separately compiled adapter is covered by the ordinary suite")
	}
	commandSource, err := filepath.Abs("testdata/projection-adapter")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "projection-adapter")
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Minute)
	defer cancel()
	if output, err := ownedcmd.CombinedOutput(ctx, "go", "build", "-p=1", "-o", path, commandSource); err != nil {
		t.Fatalf("building independent adapter: %v\n%s", err, output)
	}
	plan := tektonTestPlan(t)
	oracle, err := renderTekton(t.Context(), plan)
	if err != nil {
		t.Fatal(err)
	}
	for _, driver := range []struct {
		name            string
		adapter         *ProjectionAdapter
		calls, launches int
	}{
		{"built-in", nil, 2, 0},
		{"in-process", &ProjectionAdapter{Transport: ProjectionInProcess, Release: projectionTestRelease}, 2, 0},
		{"compiled-command", &ProjectionAdapter{Transport: ProjectionOutOfProcess, Path: path,
			Args: []string{"--engine", EngineTekton, "--release", projectionTestRelease}, Release: projectionTestRelease}, 0, 2},
	} {
		t.Run(driver.name, func(t *testing.T) {
			ctx := t.Context()
			if driver.adapter != nil {
				ctx = WithProjectionAdapter(ctx, *driver.adapter)
			}
			record := recordProjectionLaunches(t)
			got, err := Render(ctx, plan, EngineTekton)
			if err != nil || !reflect.DeepEqual(got, oracle) {
				t.Fatalf("projection differs from core: %v", err)
			}
			if record.calls != driver.calls || record.launches != driver.launches || record.plans != 1 {
				t.Fatalf("contract calls = %+v, want %d calls, %d launches and one Plan", record, driver.calls, driver.launches)
			}
			root := t.TempDir()
			for _, check := range []bool{false, true} {
				digest, err := Generate(ctx, plan, EngineTekton, root, check)
				if err != nil || digest != oracle.PlanDigest {
					t.Fatalf("Generate(check=%t): digest=%s error=%v", check, digest, err)
				}
			}
			if err := CheckGenerated(leakedProjectionSelection(ctx), plan, EngineTekton, root); err != nil {
				t.Fatal(err)
			}
			if err := CheckGeneratedBundle(ctx, root, oracle); err != nil {
				t.Fatal(err)
			}
		})
	}
	// A real command describing the other admitted engine cannot receive Plan
	// bytes, even though it speaks the same framing protocol and release.
	t.Run("wrong engine before Plan", func(t *testing.T) {
		record := recordProjectionLaunches(t)
		adapter := ProjectionAdapter{Transport: ProjectionOutOfProcess, Path: path,
			Args: []string{"--engine", EngineGitHub, "--release", projectionTestRelease}, Release: projectionTestRelease}
		root := t.TempDir()
		_, err := Generate(WithProjectionAdapter(t.Context(), adapter), plan, EngineTekton, root, false)
		assertFactoryErrorCode(t, err, e.CodeEngineCapability)
		if record.launches != 1 || record.plans != 0 {
			t.Fatalf("mismatch delivered Plan bytes: %+v", record)
		}
		assertProjectionDirectoryEmpty(t, root)
	})
}

func assertProjectionDirectoryEmpty(t *testing.T, root string) {
	t.Helper()
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 0 {
		t.Fatalf("refused generation left partial output: %v, %v", entries, err)
	}
}

func TestTektonProjectionRejectsNilContext(t *testing.T) {
	plan := tektonTestPlan(t)
	var ctx context.Context
	t.Run("render", func(t *testing.T) {
		bundle, err := Render(ctx, plan, EngineTekton)
		assertFactoryErrorCode(t, err, e.CodeUsage)
		if bundle != nil {
			t.Fatal("nil context returned a bundle")
		}
	})
	for _, check := range []bool{false, true} {
		name := "write"
		if check {
			name = "check"
		}
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			digest, err := Generate(ctx, plan, EngineTekton, root, check)
			assertFactoryErrorCode(t, err, e.CodeUsage)
			if digest != "" {
				t.Fatal("nil context returned a Plan digest")
			}
			assertProjectionDirectoryEmpty(t, root)
		})
	}
}

func TestTektonProjectionAdmitsCapabilitiesBeforeAdapter(t *testing.T) {
	plan := githubTestPlan(t)
	if err := plan.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, transport := range []ProjectionTransport{"", ProjectionInProcess, ProjectionOutOfProcess} {
		name := string(transport)
		if name == "" {
			name = "built-in"
		}
		t.Run(name, func(t *testing.T) {
			previous := launchProjectionAdapter
			launchProjectionAdapter = func(context.Context, ProjectionAdapter, []byte, int) ([]byte, error) {
				t.Fatal("unsupported Tekton Plan reached the adapter launcher")
				return nil, nil
			}
			t.Cleanup(func() { launchProjectionAdapter = previous })
			record := recordProjectionLaunches(t)
			ctx := t.Context()
			if transport != "" {
				adapter := ProjectionAdapter{Transport: transport, Release: projectionTestRelease}
				if transport == ProjectionOutOfProcess {
					adapter.Path = filepath.Join(t.TempDir(), "adapter")
				}
				ctx = WithProjectionAdapter(ctx, adapter)
			}
			root := t.TempDir()
			digest, err := Generate(ctx, plan, EngineTekton, root, false)
			assertFactoryErrorCode(t, err, e.CodeEngineCapability)
			if digest != "" || *record != (projectionLaunches{}) {
				t.Fatalf("unsupported Plan reached the adapter: digest=%q calls=%+v", digest, record)
			}
			assertProjectionDirectoryEmpty(t, root)
		})
	}
}

func TestValidateTektonBundleMetadata(t *testing.T) {
	plan := tektonTestPlan(t)
	bundle, err := renderTekton(t.Context(), plan)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		omit   bool
		mutate func(*GeneratedBundle)
	}{
		{name: "valid"},
		{name: "nil", omit: true},
		{name: "engine", mutate: func(b *GeneratedBundle) { b.Engine = EngineGitHub }},
		{name: "workflow path", mutate: func(b *GeneratedBundle) { b.WorkflowPath = "other/workflow.json" }},
		{name: "manifest path", mutate: func(b *GeneratedBundle) { b.ManifestPath = "other/manifest.json" }},
		{name: "Plan path", mutate: func(b *GeneratedBundle) { b.PlanPath = "other/plan.json" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			// Copy metadata only; every candidate retains the exact same Files.
			candidate := *bundle
			if test.mutate != nil {
				test.mutate(&candidate)
			}
			input := &candidate
			if test.omit {
				input = nil
			}
			err := ValidateTektonBundle(t.Context(), plan, input)
			if test.name == "valid" {
				if err != nil {
					t.Fatal(err)
				}
			} else {
				assertFactoryErrorCode(t, err, e.CodePipelineDrift)
			}
		})
	}
}

func TestProjectionUnknownEngineAdmittedBeforeIO(t *testing.T) {
	for _, engine := range []string{"unknown", EngineGitLab, EngineArgo, "local"} {
		t.Run(engine, func(t *testing.T) {
			want := e.CodeEngineCapability
			if engine == "unknown" || engine == "local" {
				want = e.CodeUsage
			}
			forbidGenerationSeam(t)
			root := t.TempDir()
			_, err := Generate(leakedProjectionSelection(t.Context()), nil, engine, root, false)
			assertFactoryErrorCode(t, err, want)
			assertProjectionDirectoryEmpty(t, root)
			// nil streams panic if read or written: engine admission precedes I/O.
			err = ServeProjectionAdapterForEngine(t.Context(), engine, projectionTestRelease, nil, nil)
			assertFactoryErrorCode(t, err, want)
		})
	}
}

func TestTektonProjectionServingDescription(t *testing.T) {
	frame, err := encodeProjectionFrame(projectionRequest{Protocol: projectionProtocol})
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := ServeProjectionAdapterForEngine(t.Context(), " TEKTON ", projectionTestRelease, bytes.NewReader(frame), &output); err != nil {
		t.Fatal(err)
	}
	var description projectionDescription
	if err := decodeProjectionFrame(output.Bytes(), &description, e.CodePipelineDrift); err != nil {
		t.Fatal(err)
	}
	want := projectionDescription{Protocol: projectionProtocol, Release: projectionTestRelease, Engine: EngineTekton,
		PlanSchema: PlanSchemaVersion, GeneratorABI: projectionGeneratorABI}
	if description != want {
		t.Fatalf("description = %+v, want %+v", description, want)
	}
}
