#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Fork-only assembly experiment. Never uploads or publishes runtime binaries."""

import argparse
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import shutil
import shlex
import signal
import subprocess
import sys
import tarfile
import time
import urllib.parse
import zipfile


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def record(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def fields(text):
    for paragraph in text.split("\n\n"):
        result = {}
        for line in paragraph.splitlines():
            if line and not line[0].isspace() and ": " in line:
                key, value = line.split(": ", 1)
                result[key] = value
        if result:
            yield result


def run(command, log, *, env=None, timeout=900):
    with log.open("a") as output:
        output.write("COMMAND " + repr([str(c) for c in command]) + "\n")
        output.flush()
        child = subprocess.Popen(command, stdout=output, stderr=subprocess.STDOUT,
                                 env=env, start_new_session=True)
        try:
            code = child.wait(timeout=timeout)
        except BaseException:
            os.killpg(child.pid, signal.SIGKILL)
            child.wait()
            raise
        if code:
            raise RuntimeError(f"command failed ({code}); see {log.name}")


def sources(pins, release):
    suites = " ".join([release, release + "-updates", release + "-security"])
    return ("Types: deb\n"
            f"URIs: https://snapshot.ubuntu.com/ubuntu/{pins['snapshot']}\n"
            f"Suites: {suites}\nComponents: main universe\n"
            "Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg\n")


def apt_configuration(root, name, pins):
    config = root / "apt" / name
    config.mkdir(parents=True, exist_ok=True)
    (config / "sources.list.d").mkdir(exist_ok=True)
    (config / "apt.conf.d").mkdir(exist_ok=True)
    (config / "sources.list.d/mkosi.sources").write_text(sources(pins, pins["roots"][name]["release"]))
    (config / "apt.conf").write_text(
        f'Dir::Etc "{config}";\n'
        'Acquire::Retries "2";\nAcquire::https::Timeout "60";\n'
        'Acquire::Check-Valid-Until "false";\n'
        'APT::Install-Recommends "false";\nAPT::Sandbox::User "root";\n')
    return config


def download_packages(root, cache, plan, indexes, snapshot):
    prefix = f"https://snapshot.ubuntu.com/ubuntu/{snapshot}/"
    requested = {}
    for line in plan.read_text().splitlines():
        if not line.startswith("'"):
            continue
        uri, filename, size, _ = shlex.split(line)
        if not uri.startswith(prefix) or Path(filename).name != filename or not filename.endswith(".deb"):
            raise RuntimeError("APT download plan escaped pinned snapshot or cache")
        package_path = urllib.parse.unquote(uri[len(prefix):])
        if package_path in requested:
            raise RuntimeError("duplicate package in APT download plan")
        requested[package_path] = (uri, cache / "cache/apt/archives" / filename, int(size))
    if not requested:
        raise RuntimeError("empty APT download plan")
    closure = {}
    for index in indexes:
        data = subprocess.run(["/usr/lib/apt/apt-helper", "cat-file", str(index)],
                              check=True, capture_output=True, timeout=120).stdout.decode()
        for package in fields(data):
            filename = package.get("Filename")
            if filename in requested:
                if int(package["Size"]) != requested[filename][2]:
                    raise RuntimeError("APT plan and signed index size differ")
                if filename in closure and closure[filename]["SHA256"] != package["SHA256"]:
                    raise RuntimeError("conflicting package hashes in signed indexes")
                closure[filename] = package
    if set(closure) != set(requested):
        raise RuntimeError("APT plan package absent from authenticated snapshot indexes")

    def fetch(filename):
        uri, destination, size = requested[filename]
        result = subprocess.run([
            "curl", "--fail", "--location", "--connect-timeout", "10", "--max-time", "180",
            "--retry", "2", "--retry-delay", "3", "--retry-max-time", "540",
            "--max-filesize", str(size), "--output", str(destination), uri,
        ], capture_output=True, text=True, timeout=560)
        if result.returncode:
            raise RuntimeError(f"download failed: {filename}: {result.stderr[-2000:]}")
        if destination.stat().st_size != size or digest(destination) != closure[filename]["SHA256"]:
            raise RuntimeError(f"package digest mismatch: {filename}")

    print(f"Acquiring {len(requested)} authenticated packages with four workers", flush=True)
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        futures = [executor.submit(fetch, filename) for filename in sorted(requested)]
        try:
            for count, future in enumerate(concurrent.futures.as_completed(futures), 1):
                future.result()
                if count % 25 == 0 or count == len(futures):
                    print(f"Verified {count}/{len(futures)} downloaded packages", flush=True)
        except BaseException:
            for future in futures:
                future.cancel()
            raise
    return sorted(closure.values(), key=lambda p: (p["Package"], p["Version"])), {
        str(destination.relative_to(root)): closure[filename]["SHA256"]
        for filename, (_, destination, _) in requested.items()
    }


def acquire(root, pins):
    records = root / "records"
    records.mkdir(parents=True, exist_ok=True)
    log = records / "acquisition.log"
    start = time.monotonic()
    for name, spec in pins["roots"].items():
        cache = root / "packages" / name
        for directory in ["lib/apt/lists/partial", "cache/apt/archives/partial", "empty", "log"]:
            (cache / directory).mkdir(parents=True, exist_ok=True)
        status = cache / "empty/status"
        status.write_text("")
        config = apt_configuration(root, name, pins)
        env = dict(os.environ, APT_CONFIG=str(config / "apt.conf"), LC_ALL="C.UTF-8")
        command = ["apt-get", "-o", f"Dir::State::status={status}",
                   "-o", f"Dir::State={cache / 'lib/apt'}",
                   "-o", f"Dir::Cache={cache / 'cache/apt'}",
                   "-o", f"Dir::State::lists={cache / 'lib/apt/lists'}",
                   "-o", f"Dir::Cache::archives={cache / 'cache/apt/archives'}",
                   "-o", f"Dir::Log={cache / 'log'}", "-o", "APT::Architecture=amd64",
                   "-o", "APT::Architectures=amd64", "-o", "APT::Get::Assume-Yes=true"]
        run([*command, "update", "--error-on=any"], log, env=env)
        metadata = {}
        for suite in [spec["release"], spec["release"] + "-updates", spec["release"] + "-security"]:
            matches = list((cache / "lib/apt/lists").glob(f"*_dists_{suite}_InRelease"))
            if len(matches) != 1 or digest(matches[0]) != pins["inReleaseSHA256"][suite]:
                raise RuntimeError(f"snapshot metadata pin mismatch: {suite}")
            metadata[suite] = digest(matches[0])
        # Resolve against empty state, then download only those exact packages.
        # No package installation or host package-state change is possible here.
        plan = records / f"{name}-download-plan.log"
        run([*command, "install", "--download-only", "--print-uris", "?essential", "base-files",
             *spec["packages"]], plan, env=env, timeout=120)
        closure, cache_files = download_packages(root, cache, plan,
            sorted((cache / "lib/apt/lists").glob("*_Packages*")), pins["snapshot"])
        record(records / f"{name}-package-inputs.json", {
            "snapshot": pins["snapshot"], "inReleaseSHA256": metadata,
            "packages": closure, "cacheFiles": cache_files,
            "metadataFiles": {str(p.relative_to(root)): digest(p)
                              for p in sorted((cache / "lib/apt/lists").iterdir())
                              if p.is_file() and p.name != "lock"},
        })
    extras = root / "extras"
    for key, project in [("packer", "packer"), ("qemuPlugin", "packer-plugin-qemu")]:
        pin = pins[key]
        version = pin["version"]
        archive = root / f"{project}.zip"
        run(["curl", "--fail", "--location", "--connect-timeout", "10", "--max-time", "180",
             "--retry", "2", "--retry-delay", "3", "--retry-max-time", "540",
             "--max-filesize", "268435456", "--output", str(archive),
             f"https://releases.hashicorp.com/{project}/{version}/{project}_{version}_linux_amd64.zip"], log)
        if digest(archive) != pin["archives"]["amd64"].removeprefix("sha256:"):
            raise RuntimeError(f"{project} archive pin mismatch")
        binary = "packer" if key == "packer" else f"packer-plugin-qemu_v{version}_x5.0_linux_amd64"
        target = (extras / "usr/local/bin/packer" if key == "packer" else
                  extras / "nvkr/toolchain/packer/plugins/github.com/hashicorp/qemu" / binary)
        target.parent.mkdir(parents=True, exist_ok=True)
        license_file = extras / "usr/share/licenses" / project / "LICENSE.txt"
        license_file.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(archive) as z:
            target.write_bytes(z.read(binary))
            license_file.write_bytes(z.read("LICENSE.txt"))
        expected = pin["binaries"]["amd64"].removeprefix("sha256:")
        if digest(target) != expected:
            raise RuntimeError(f"{project} binary pin mismatch")
        target.chmod(0o755)
        if key == "qemuPlugin":
            target.with_name(binary + "_SHA256SUM").write_text(expected)
    record(records / "acquisition.json", {"wall_seconds": time.monotonic() - start,
           "keyring_sha256": digest(Path("/usr/share/keyrings/ubuntu-archive-keyring.gpg")),
           "snapshot": pins["snapshot"], "staticToolPins": {k: pins[k] for k in ["packer", "qemuPlugin"]}})


def check_inputs(root):
    for name in ["inspect", "runtime"]:
        inputs = json.loads((root / "records" / f"{name}-package-inputs.json").read_text())
        for relative, sha in (inputs["cacheFiles"] | inputs["metadataFiles"]).items():
            if digest(root / relative) != sha:
                raise RuntimeError(f"cached package changed: {relative}")


def inventory(artifact, destination):
    result = {}
    with artifact.open("rb") as raw, tarfile.open(artifact) as archive:
        for member in archive:
            if member.name in result:
                raise RuntimeError(f"duplicate tar member {member.name}")
            entry = {key: getattr(member, key) for key in
                     ["size", "mode", "uid", "gid", "uname", "gname", "mtime", "linkname",
                      "pax_headers", "devmajor", "devminor"]}
            entry["type"] = member.type.decode("ascii")
            raw.seek(member.offset)
            entry["rawHeaderSHA256"] = hashlib.sha256(raw.read(member.offset_data - member.offset)).hexdigest()
            if member.isfile():
                with archive.extractfile(member) as stream:
                    entry["sha256"] = hashlib.file_digest(stream, "sha256").hexdigest()
            result[member.name] = entry
    record(destination, result)
    return result


def build(root, pins, module, attempt):
    if Path("/dev/kvm").exists():
        raise RuntimeError("KVM must not be visible")
    check_inputs(root)
    work = root / f"build-{attempt}"
    work.mkdir()
    records = root / "records"
    env = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "PYTHONPATH": str(module),
           "HOME": str(work), "LC_ALL": "C.UTF-8", "SOURCE_DATE_EPOCH": "0"}
    phases = {}
    start = time.monotonic()
    for name in ["inspect", "runtime"]:
        spec = pins["roots"][name]
        config = work / name
        config.mkdir()
        sandbox = config / "mkosi.sandbox/etc/apt"
        sandbox.mkdir(parents=True)
        shutil.copytree(root / "apt" / name / "sources.list.d", sandbox / "sources.list.d")
        (sandbox / "apt.conf.d").mkdir()
        (sandbox / "apt.conf.d/99-proof").write_text('Acquire::Retries "0";\n')
        output_format = "directory" if name == "inspect" else "tar"
        content = (f"[Distribution]\nDistribution={pins['distribution']}\nRelease={spec['release']}\n"
                   "Architecture=x86-64\nRepositories=universe\n"
                   f"[Output]\nFormat={output_format}\nOutput={name}\nCompressOutput=no\n"
                   "[Content]\nBootable=no\nSourceDateEpoch=0\nWithDocs=yes\nWithRecommends=no\nCleanPackageMetadata=no\n"
                   "Packages=" + ",".join(spec["packages"]) + "\n")
        if name == "runtime":
            content += f"ExtraTrees={root / 'extras'}\n           {work / 'inspect/output/inspect'}:/opt/nvkr/inspection\n"
        content += "[Build]\nBuildSources=\nCacheKey=proof\n"
        (config / "mkosi.conf").write_text(content)
        for directory in ["output", "cache"]:
            (config / directory).mkdir()
        # mkosi keeps repository metadata separate from downloaded packages.
        # Seed its explicit cache key with the authenticated, rehashed lists.
        shutil.copytree(root / "packages" / name / "lib/apt/lists",
                        config / "cache/proof.metadata.cache/lib/apt/lists")
        workspace = work / f"{name}-workspace"
        workspace.mkdir()
        command = [sys.executable, "-m", "mkosi", "--debug", f"--directory={config}",
                   f"--output-directory={config / 'output'}", f"--workspace-directory={workspace}",
                   f"--cache-directory={config / 'cache'}", f"--package-cache-directory={root / 'packages' / name}",
                   "--cache-only=always", "--incremental=no", "build"]
        phase_start = time.monotonic()
        run(command, records / f"build-{attempt}-{name}.log", env=env, timeout=1200)
        phases[name] = time.monotonic() - phase_start
        if name == "inspect":
            inspect_root = config / "output/inspect"
            kernels = list((inspect_root / "boot").glob("vmlinuz-6.8.0-149*"))
            if len(kernels) != 1:
                raise RuntimeError("pinned inspection kernel missing or ambiguous")
            kernels[0].chmod(0o644)
            run(["chroot", str(inspect_root), "/usr/bin/guestfish", "--version"],
                records / f"build-{attempt}-checks.log", timeout=30)
            run(["chroot", str(inspect_root), "/usr/bin/qemu-system-x86_64", "--version"],
                records / f"build-{attempt}-checks.log", timeout=30)
    artifact = work / "runtime/output/runtime.tar"
    entries = inventory(artifact, records / f"build-{attempt}-inventory.json")
    installed = {}
    with tarfile.open(artifact) as archive:
        for name, prefix in [("runtime", "."), ("inspect", "./opt/nvkr/inspection")]:
            with archive.extractfile(prefix + "/var/lib/dpkg/status") as stream:
                packages = [p for p in fields(stream.read().decode())
                            if p.get("Status") == "install ok installed"]
            installed[name] = sorted(packages, key=lambda p: p["Package"])
            by_name = {p["Package"]: p["Version"] for p in packages}
            for requested in pins["roots"][name]["packages"]:
                package, _, version = requested.partition("=")
                if package not in by_name or (version and by_name[package] != version):
                    raise RuntimeError(f"installed package pin missing: {name}:{requested}")
    record(records / f"build-{attempt}-installed-packages.json", installed)
    for path, sha in pins["baseline"]["firmwareSHA256"].items():
        if entries["." + path].get("sha256") != sha:
            raise RuntimeError(f"baseline firmware mismatch: {path}")
    if entries["./usr/local/bin/packer"]["sha256"] != pins["packer"]["binaries"]["amd64"].removeprefix("sha256:"):
        raise RuntimeError("Packer output bytes mismatch")
    for path in ["./usr/bin/qemu-system-x86_64", "./usr/bin/qemu-img", "./usr/bin/xorriso",
                 "./usr/bin/cloud-localds", "./opt/nvkr/inspection/usr/bin/guestfish",
                 "./opt/nvkr/inspection/usr/bin/virt-inspector"]:
        if path not in entries:
            raise RuntimeError(f"runtime tool absent: {path}")
    record(records / f"build-{attempt}-result.json", {"built": True, "sha256": digest(artifact),
           "bytes": artifact.stat().st_size, "mkosi_phase_wall_seconds": phases,
           "total_seconds_including_validation": time.monotonic() - start,
           "kernel": os.uname().release, "architecture": os.uname().machine,
           "kvm_present": False, "member_count": len(entries)})


def compare(root):
    records = root / "records"
    results = [json.loads((records / f"build-{n}-result.json").read_text()) for n in [1, 2]]
    inventories = [json.loads((records / f"build-{n}-inventory.json").read_text()) for n in [1, 2]]
    left, right = inventories
    missing = sorted(set(left) ^ set(right))
    changed = {name: {"first": left[name], "second": right[name]} for name in sorted(set(left) & set(right))
               if left[name] != right[name]}
    order = []
    for n in [1, 2]:
        with tarfile.open(root / f"build-{n}/runtime/output/runtime.tar") as tar:
            order.append([m.name for m in tar])
    record(records / "comparison.json", {"byte_digest_equal": results[0]["sha256"] == results[1]["sha256"],
           "results": results, "missing_members": missing, "changed_member_count": len(changed),
           "changed_members": changed, "member_order_equal": order[0] == order[1]})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=["acquire", "build", "compare"])
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--pins", type=Path, required=True)
    parser.add_argument("--module", type=Path)
    parser.add_argument("--attempt", type=int, choices=[1, 2])
    args = parser.parse_args()
    pins = json.loads(args.pins.read_text())
    if pins["architecture"] != "amd64" or pins["packageManager"] != "apt":
        parser.error("this proof currently admits amd64 with APT only")
    if args.mode == "acquire":
        acquire(args.root, pins)
    elif args.mode == "build":
        if args.module is None or args.attempt is None:
            parser.error("build requires module and attempt")
        build(args.root, pins, args.module, args.attempt)
    else:
        compare(args.root)


if __name__ == "__main__":
    main()
