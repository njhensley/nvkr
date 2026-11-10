#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Experimental local transport only. No cloud credentials, production Release,
# keyless signing, or qualified lane. All runtime state stays outside the repo.
set -euo pipefail
root=$(git -C "$(dirname "${BASH_SOURCE[0]}")" rev-parse --show-toplevel)
export GOTOOLCHAIN=local
required_go=$(cat "$root/.go-version")
nvkr_go=$(command -v go)
if [[ "$($nvkr_go version)" != "go version go$required_go "* ]]; then
  cached_go="$(go env GOMODCACHE)/golang.org/toolchain@v0.0.1-go${required_go}.$(go env GOOS)-$(go env GOARCH)/bin/go"
  if [[ ! -x "$cached_go" ]]; then
    echo "Install Go $required_go before running this experiment" >&2
    exit 2
  fi
  nvkr_go=$cached_go
fi
data=${S3_EXPERIMENT_DATA:-$(mktemp -d "${TMPDIR:-/tmp}/nvkr-s3-experiment.XXXXXX")}
mkdir -p "$data"
data=$(realpath "$data")
case "$data/" in "$root/"*) echo 'Runtime data must be outside the checkout' >&2; exit 2;; esac
if [[ -e "$data/state/release.ref" ]]; then
  echo 'Use a fresh S3_EXPERIMENT_DATA directory for each run' >&2
  exit 2
fi

run() (
  set -euo pipefail
  s3_id='' registry_id=''
  # shellcheck disable=SC2329 # invoked through EXIT trap
  cleanup() {
    result=$?
    trap - EXIT
    if [[ -n "$s3_id" ]]; then
      docker logs "$s3_id" > "$data/s3-container.log" 2>&1 || true
      docker stop --time 10 "$s3_id" >/dev/null || result=1
    fi
    if [[ -n "$registry_id" ]]; then
      docker logs "$registry_id" > "$data/registry-container.log" 2>&1 || true
      docker stop --time 10 "$registry_id" >/dev/null || result=1
    fi
    echo "DOWN: experiment containers stopped (exit=$result)"
    exit "$result"
  }
  trap cleanup EXIT
  trap 'exit 130' INT TERM
  export GOTOOLCHAIN=local GOMAXPROCS=2
  s3_image='chrislusf/seaweedfs@sha256:ccad23e18639c8b98cee17e7100b95830a06077b56d8e5b006d6dcf8ec5e94a0'
  registry_image='registry@sha256:a3d8aaa63ed8681a604f1dea0aa03f100d5895b6a58ace528858a7b332415373'
  echo 'EXPERIMENT: local S3 + OCI transport, static-unqualified'
  echo "Source: $(git -C "$root" rev-parse HEAD)"
  echo "S3 image: $s3_image (authorized SeaweedFS fallback; MinIO images unavailable)"
  echo "Registry image: $registry_image"
  echo "Evidence: $data"
  docker pull "$s3_image"
  docker pull "$registry_image"
  cat > "$data/s3-config.json" <<'JSON'
{"identities":[{"name":"local-experiment","credentials":[{"accessKey":"nvkr-local-test","secretKey":"nvkr-local-test-secret"}],"actions":["Admin","Read","Write"]}]}
JSON
  s3_id=$(docker run --rm -d --cpus=1 --memory=512m -p 127.0.0.1::8333 \
    -v "$data/s3-config.json:/etc/nvkr-s3.json:ro" "$s3_image" mini \
    -dir=/data -s3.config=/etc/nvkr-s3.json -bucket=nvkr-experiment \
    -master.telemetry=false -volume.max=2 -master.volumeSizeLimitMB=128 \
    -webdav=false -admin.ui=false -s3.port.iceberg=0 -s3.port.lance=0)
  registry_id=$(docker run --rm -d --cpus=1 --memory=256m -p 127.0.0.1::5000 "$registry_image")
  endpoint="http://$(docker port "$s3_id" 8333/tcp)"
  registry_host=$(docker port "$registry_id" 5000/tcp)
  ready=false
  for ((attempt=0; attempt<60; attempt++)); do
    code=$(curl --silent --max-time 1 --output /dev/null --write-out '%{http_code}' "$endpoint/nvkr-experiment" || true)
    if [[ "$code" == 403 || "$code" == 200 ]] && curl --fail --silent --max-time 1 "http://$registry_host/v2/" >/dev/null; then
      ready=true; break
    fi
    sleep 1
  done
  [[ "$ready" == true ]] || { echo 'Local services did not become ready' >&2; exit 1; }
  echo "UP: S3 $endpoint; OCI $registry_host"
  # Build the repository's real CLI; no QCOW build or synthetic payload.
  (cd "$root" && "$nvkr_go" build -p 2 -trimpath -ldflags='-s -w' -o "$data/nvkr" ./cmd/nvkr)
  (cd "$root" && "$nvkr_go" build -p 2 -tags s3experiment -o "$data/nvkr-s3-experiment" ./cmd/nvkr-s3-experiment)
  helper="$data/nvkr-s3-experiment"
  "$helper" -mode publish -endpoint "$endpoint" -repository "$registry_host/nvkr/releases" -artifact "$data/nvkr" -state "$data/state"
  "$helper" -mode verify -endpoint "$endpoint" -state "$data/state"
  cmp "$data/nvkr" "$data/state/downloaded/nvkr"
  echo 'Independent download matches the built CLI byte for byte'
  "$helper" -mode tamper -endpoint "$endpoint" -state "$data/state"
  set +e
  "$helper" -mode verify -endpoint "$endpoint" -state "$data/state" > "$data/tamper.log" 2>&1
  result=$?
  set -e
  cat "$data/tamper.log"
  # Require the S3 integrity failure, not an unrelated process or output failure.
  if [[ "$result" -eq 0 ]] || ! grep -q 'S3 verification failed for nvkr' "$data/tamper.log"; then
    echo "FAIL: expected S3 tamper rejection, got exit=$result" >&2
    exit 1
  fi
  echo "VERIFY FAILS AS EXPECTED: tampered S3 object rejected (exit=$result)"
  echo 'PASS: publish -> OCI-led verification -> same-size S3 tamper rejection'
)
run 2>&1 | tee "$data/run.log"
