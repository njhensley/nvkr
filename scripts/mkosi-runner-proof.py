#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Disposable mkosi assembly proof, not an NVKR producer or evidence issuer."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import resource
import shutil
import signal
import subprocess
import sys
import tarfile
import time


def allocated_bytes(root):
    """Allocated blocks; do not follow links or count hard links twice."""
    total = 0
    seen = set()
    for directory, dirs, files in os.walk(root, followlinks=False):
        for entry in [Path(directory), *(Path(directory) / n for n in dirs + files)]:
            try:
                st = entry.lstat()
            except FileNotFoundError:
                continue
            key = (st.st_dev, st.st_ino)
            if key not in seen:
                total += st.st_blocks * 512
                seen.add(key)
    return total


def process_tree_rss(pid):
    pending = [pid]
    seen = set()
    rss = 0
    while pending:
        current = pending.pop()
        if current in seen:
            continue
        seen.add(current)
        try:
            status = Path(f"/proc/{current}/status").read_text()
            for line in status.splitlines():
                if line.startswith("VmRSS:"):
                    rss += int(line.split()[1]) * 1024
            children = Path(f"/proc/{current}/task/{current}/children").read_text()
            pending.extend(int(child) for child in children.split())
        except (FileNotFoundError, ProcessLookupError):
            continue
    return rss


def cgroup_peak():
    for line in Path("/proc/self/cgroup").read_text().splitlines():
        if line.startswith("0::"):
            relative = line[3:].lstrip("/")
            path = Path("/sys/fs/cgroup") / relative / "memory.peak"
            if path.is_file():
                return {"path": str(path), "bytes": int(path.read_text())}
    return None


def inspect_archive(path):
    entries = []
    expected = {
        "usr/lib/os-release": b'ID=nvkr-proof\nNAME="NVKR mkosi proof"\nVERSION_ID=1\n',
        "usr/share/nvkr-feasibility/marker": b"mkosi assembly without KVM\n",
    }
    found = set()
    with tarfile.open(path) as archive:
        for member in archive.getmembers():
            name = member.name.removeprefix("./")
            entry = {
                "name": name,
                "type": member.type.decode("ascii"),
                "size": member.size,
                "mode": member.mode,
                "uid": member.uid,
                "gid": member.gid,
                "uname": member.uname,
                "gname": member.gname,
                "mtime": member.mtime,
                "linkname": member.linkname,
                "pax_headers": member.pax_headers,
            }
            if member.isfile():
                with archive.extractfile(member) as stream:
                    content = stream.read()
                entry["sha256"] = hashlib.sha256(content).hexdigest()
                if name in expected:
                    if content != expected[name]:
                        raise ValueError(f"wrong content for {name}")
                    found.add(name)
            entries.append(entry)
    if found != set(expected):
        raise ValueError(f"missing proof files: {set(expected) - found}")
    return sorted(entries, key=lambda entry: entry["name"])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mkosi-module", type=Path, required=True)
    parser.add_argument("--fixture", type=Path, required=True)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--memory-scope", required=True)
    args = parser.parse_args()
    if sys.platform != "linux":
        parser.error("Linux is required")
    root = args.root.resolve()
    root.mkdir(parents=True, exist_ok=False)
    for name in ["output", "workspace", "cache", "pkgcache", "tmp", "home", "results"]:
        (root / name).mkdir()
    shutil.copytree(args.fixture.resolve(), root / "input", symlinks=True)
    results = root / "results"
    env = {
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "PYTHONPATH": str(args.mkosi_module.resolve()),
        "HOME": str(root / "home"),
        "TMPDIR": str(root / "tmp"),
        "LC_ALL": "C.UTF-8",
        "SOURCE_DATE_EPOCH": "0",
    }
    command = [
        sys.executable, "-m", "mkosi", "--debug",
        f"--directory={root / 'input'}",
        f"--output-directory={root / 'output'}",
        f"--workspace-directory={root / 'workspace'}",
        f"--cache-directory={root / 'cache'}",
        f"--package-cache-directory={root / 'pkgcache'}",
        "--incremental=no", "build",
    ]
    metrics = {
        "command": command,
        "kernel": os.uname().release,
        "architecture": os.uname().machine,
        "python": sys.version,
        "cpu_count": os.cpu_count(),
        "load_average_before": os.getloadavg(),
        "kvm_present": Path("/dev/kvm").exists(),
        "memory_scope": args.memory_scope,
        "cgroup_peak_before": cgroup_peak(),
        "sampling_interval_seconds": 0.02,
        "disk_scope": "allocated blocks beneath proof root; excludes tools, base images and downloads",
        "disk_initial_allocated_bytes": allocated_bytes(root),
    }
    if metrics["kvm_present"]:
        raise RuntimeError("proof must not expose /dev/kvm")
    (results / "host-status.txt").write_text(Path("/proc/self/status").read_text())
    with (results / "versions.txt").open("w") as versions:
        for version_command in [[sys.executable, "-m", "mkosi", "--version"], ["tar", "--version"]]:
            subprocess.run(version_command, env=env, stdout=versions, stderr=subprocess.STDOUT,
                           check=True, timeout=10)
    peak_disk = metrics["disk_initial_allocated_bytes"]
    peak_rss = 0
    samples = 0
    started = time.monotonic()
    with (results / "mkosi.log").open("w") as log:
        child = subprocess.Popen(command, env=env, stdout=log, stderr=subprocess.STDOUT,
                                 start_new_session=True)
        try:
            while child.poll() is None:
                if time.monotonic() - started > 120:
                    raise TimeoutError("mkosi exceeded 120 seconds")
                peak_disk = max(peak_disk, allocated_bytes(root))
                peak_rss = max(peak_rss, process_tree_rss(child.pid))
                samples += 1
                time.sleep(0.02)
        except BaseException:
            os.killpg(child.pid, signal.SIGKILL)
            child.wait()
            raise
        finally:
            metrics["mkosi_wall_seconds"] = time.monotonic() - started
            metrics["exit_code"] = child.poll()
            metrics["sample_count"] = samples
            metrics["sampled_peak_disk_allocated_bytes"] = max(peak_disk, allocated_bytes(root))
            metrics["sampled_peak_process_tree_rss_bytes"] = peak_rss
            metrics["largest_child_peak_rss_kib"] = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
            metrics["cgroup_peak_after"] = cgroup_peak()
            (results / "metrics.json").write_text(json.dumps(metrics, indent=2) + "\n")
    if child.returncode:
        print((results / "mkosi.log").read_text(), file=sys.stderr)
        return child.returncode
    artifact = root / "output/probe.tar"
    inventory = inspect_archive(artifact)
    shutil.copyfile(artifact, results / "probe.tar")
    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
    (results / "probe.sha256").write_text(f"{digest}  probe.tar\n")
    (results / "inventory.json").write_text(json.dumps(inventory, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"image_built": True, "sha256": digest, "bytes": artifact.stat().st_size,
                      "metrics": metrics}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
