#!/usr/bin/env python3
"""Compile README/guide examples using Cargo's stable artifact-message protocol."""

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys


def build_artifacts(root, arguments):
    environment = dict(
        os.environ, CARGO_TARGET_DIR=str((root / arguments.target_dir).resolve())
    )
    command = [
        "cargo",
        f"+{arguments.toolchain}",
        "build",
        "--all-features",
        "--locked",
        "--message-format=json",
    ]
    if arguments.examples:
        command.append("--examples")
    artifacts = []
    with subprocess.Popen(
        command, cwd=root, env=environment, stdout=subprocess.PIPE, text=True
    ) as process:
        for line in process.stdout:
            if not line.startswith("{"):
                print(line, end="", file=sys.stderr)
                continue
            message = json.loads(line)
            if message.get("reason") == "compiler-artifact":
                artifacts.append(message)
            elif message.get("reason") == "compiler-message":
                print(
                    message["message"].get("rendered") or message["message"]["message"],
                    file=sys.stderr,
                )
        if process.wait():
            raise SystemExit(process.returncode)
    return artifacts


def packages(root, arguments):
    metadata = json.loads(
        subprocess.check_output(
            [
                "cargo",
                f"+{arguments.toolchain}",
                "metadata",
                "--all-features",
                "--locked",
                "--format-version=1",
            ],
            cwd=root,
            text=True,
        )
    )
    owned = [
        package
        for package in metadata["packages"]
        if package["name"] == arguments.package
        and Path(package["manifest_path"]).resolve() == root / "Cargo.toml"
    ]
    if len(owned) != 1:
        raise SystemExit("Cargo metadata must identify exactly one owned root package")
    selected = {arguments.package.replace("-", "_"): owned[0]}
    node = next(
        node for node in metadata["resolve"]["nodes"] if node["id"] == owned[0]["id"]
    )
    for alias in arguments.extern:
        identifiers = {
            dependency["pkg"]
            for dependency in node["deps"]
            if dependency["name"] == alias
        }
        if len(identifiers) != 1:
            raise SystemExit(
                f"Cargo must resolve exactly one direct dependency for {alias}"
            )
        selected[alias] = next(
            package for package in metadata["packages"] if package["id"] in identifiers
        )
    return selected


def library(artifacts, package, name):
    candidates = {
        Path(filename).resolve()
        for artifact in artifacts
        if artifact["package_id"] == package["id"]
        and Path(artifact["manifest_path"]).resolve()
        == Path(package["manifest_path"]).resolve()
        and artifact["target"]["name"] == name
        and "lib" in artifact["target"]["kind"]
        for filename in artifact["filenames"]
        if filename.endswith(".rlib")
    }
    if len(candidates) != 1 or not next(iter(candidates)).is_file():
        raise SystemExit(
            f"Cargo must report exactly one existing library artifact for {name}"
        )
    return candidates.pop()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", required=True)
    parser.add_argument("--toolchain", required=True)
    parser.add_argument("--target-dir", required=True, type=Path)
    parser.add_argument("--extern", action="append", default=[])
    parser.add_argument("--examples", action="store_true")
    parser.add_argument("--recursive", action="store_true")
    arguments = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    selected = packages(root, arguments)
    artifacts = build_artifacts(root, arguments)
    externs = {
        name: library(artifacts, package, name) for name, package in selected.items()
    }
    dependency_dirs = sorted(
        {
            str(Path(filename).resolve().parent)
            for artifact in artifacts
            for filename in artifact["filenames"]
        }
    )
    documents = (
        (root / "docs").rglob("*.md")
        if arguments.recursive
        else (root / "docs").glob("*.md")
    )
    for document in [root / "README.md", *sorted(documents)]:
        command = [
            "rustup",
            "run",
            arguments.toolchain,
            "rustdoc",
            "--test",
            str(document),
            "--edition",
            "2024",
        ]
        for name, artifact in externs.items():
            command.extend(["--extern", f"{name}={artifact}"])
        for directory in dependency_dirs:
            command.extend(["-L", f"dependency={directory}"])
        subprocess.run(command, cwd=root, check=True)


if __name__ == "__main__":
    main()
