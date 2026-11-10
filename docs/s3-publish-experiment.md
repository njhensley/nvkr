# Local S3 publication experiment

Run from this branch with Docker and the Go version in `.go-version` installed:

```sh
bash scripts/s3-experiment.sh
```

The command prints its fresh temporary evidence directory, including `run.log`,
`tamper.log`, the immutable `state/release.ref`, a public trust anchor, and the
downloaded files. Set `S3_EXPERIMENT_DATA` to a fresh absolute directory outside
the checkout to retain these at a chosen location. It reuses an already cached
matching Go toolchain if the PATH compiler differs; it never downloads Go.

The script starts digest-pinned S3-compatible storage and a Distribution registry
on ephemeral loopback ports, builds the real native NVKR CLI, publishes it,
downloads and verifies it starting from the OCI record, overwrites the S3 payload
with same-size corrupt bytes, requires verification to fail, and stops both
containers. Service data is disposable; logs and verified downloads remain.
CPU limits are one core per container and two Go build workers.

This branch uses SeaweedFS after both tagged and latest MinIO pulls failed from
Docker Hub and Quay. That fallback exercises an S3-compatible server, not MinIO or
AWS. Both image references are immutable digests in the script. The only storage
credentials are fixed public test values. No cloud identity or bucket is used.

## Publication and consumer flow

The opt-in `s3experiment` build tag enables a loopback-only constructor for
`delivery.ObjectStore`. It reuses the production S3 conditional writes, multipart
handling, pinned reads and cleanup, using the existing pinned AWS SDK for Go v2.
There are no new dependencies and no default production behavior changes.

`pkg/nvkr/s3experiment` owns publication and verification. The shell only manages
containers, builds the binary and invokes the helper. It does not upload objects.
The five S3 objects are:

- The real native `nvkr` executable built from this checkout.
- Its standard SHA-256 checksum sidecar.
- A CycloneDX 1.6 SBOM of the binary's embedded Go module dependencies. This is a
  module inventory, not a filesystem scan or complete operating-system SBOM.
- An in-toto-shaped local build observation naming the artifact SHA-256, Go
  version and embedded build settings. It claims no SLSA level or hosted Run.
- An Ed25519 signature over the canonical release payload, including every file
  locator and the destination. Its ephemeral private key never reaches disk.

Every object has an `artifacts/blobs/sha256/<hex>` physical key. The experimental
OCI document records bucket, prefix, relative object key, SHA-256, size, media type
and observed version/ETag. Its standard OCI manifest binds the exact canonical
document bytes. `delivery.PushDocumentArtifact` publishes that manifest by digest;
`delivery.PullDocumentArtifact` verifies the digest and exact wrapper on consumption.

The separate `nvkr-s3-experiment -mode verify` command needs only that OCI digest,
the independently supplied local public key and the loopback S3 endpoint. It
fetches the record from OCI, authenticates the signature, fetches every S3 file
with its recorded pin, checks full SHA-256 and size, checks the checksum sidecar,
and saves the verified downloads. The script compares the recovered binary with
the original. The tamper check requires a specific S3 verification error and a
nonzero exit, rather than accepting an unrelated command failure.

## Limits and production follow-up

This is an experimental OCI release **record**, not an issued NVKR Release or
an extension of `releasemanifest.Manifest`. Its distinct schema, media type and
`static-unqualified` lane cannot pass the production `nvkr release verify` route.
The artifact is the CLI built by this repository's Go build, not an output of a
Definition/Run execution. No QCOW2, guest, SBOM scanner, Sigstore service, OIDC or
production release gate is exercised. The build tag keeps the local credential
exception out of ordinary binaries.

ADR-20 already specifies required S3 copies of existing signed OCI publications,
and Environment v2 already has `publication.objectStores`. Its production
`MirrorExactInputs` and `VerifyObjectPublication` paths require original signer
policy, provenance, SBOMs, exact inputs and invocation joins. This experiment does
not replace those paths or weaken their hosted/TLS/temporary-identity admission.

To integrate the demonstrated reverse link into the central release route:

1. Decide where the completed S3 inventory locator belongs in authenticated
   aggregate release metadata, then version that schema and extend the owning
   release issuer and consumer. Bind it only after complete remote readback;
   avoid a cycle between the release root and the copy inventory.
2. Reuse the original signed closure and `VerifyObjectPublication` rather than
   inventing production authority from this experiment's local record/signature.
   Add a consumer CLI/SDK projection for following the locator from OCI.
3. Extend ADR-20's owning section with the discovery/linkage contract, destination
   authorization semantics and evidence scope. Preserve the distinction between
   raw payload SHA-256, OCI wrapper digests and logical Build identity.
4. Record independent provider and hosted workflow evidence, including large
   QCOW2 multipart transfers, exact-version reads, IAM denial and recovery.

Open decisions include whether the release signer authorizes an S3 destination
or merely authenticates unchanged subjects; whether original signatures suffice
or an additional delivery signature is wanted; bucket versioning/object lock and
retention/GC; how old pinned versions behave after a current-object overwrite;
consumer credentials/IAM/KMS; and whether OCI remains an obligatory source or S3
may become the primary large-payload location. Conditional content-addressed writes
alone do not enforce retention or prevent an administrator from deleting bytes.

## Focused checks

```sh
go test -tags s3experiment ./pkg/nvkr/s3experiment ./pkg/nvkr/delivery -count=1
go vet -tags s3experiment ./cmd/nvkr-s3-experiment ./pkg/nvkr/s3experiment ./pkg/nvkr/delivery
shellcheck scripts/s3-experiment.sh
```

The tests reject content corruption even if a provider preserves its ETag, missing
files, wrong keys, changed destination, wrong signer, invalid membership/schema,
and unsupported endpoints. The live run additionally exercises a real local S3
server and OCI registry; it is not provider qualification.
