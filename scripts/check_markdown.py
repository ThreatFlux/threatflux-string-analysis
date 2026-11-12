"""Resolve exact Cargo libraries and emit NUL-delimited rustdoc arguments."""

import argparse
import json
import os
import sys
from pathlib import Path


def build_artifacts(path):
    artifacts = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.startswith("{"):
            print(line, file=sys.stderr)
            continue
        message = json.loads(line)
        if message.get("reason") == "compiler-artifact":
            artifacts.append(message)
        elif message.get("reason") == "compiler-message":
            print(
                message["message"].get("rendered") or message["message"]["message"],
                file=sys.stderr,
            )
    return artifacts


def packages(root, arguments):
    metadata = json.loads(arguments.metadata.read_text(encoding="utf-8"))
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
    parser.add_argument("--metadata", required=True, type=Path)
    parser.add_argument("--artifacts", required=True, type=Path)
    parser.add_argument("--document", required=True, type=Path)
    parser.add_argument("--extern", action="append", default=[])
    arguments = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    selected = packages(root, arguments)
    artifacts = build_artifacts(arguments.artifacts)
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
    command = ["--test", str(arguments.document.resolve()), "--edition", "2024"]
    for name, artifact in externs.items():
        command.extend(["--extern", f"{name}={artifact}"])
    for directory in dependency_dirs:
        command.extend(["-L", f"dependency={directory}"])
    sys.stdout.buffer.write(
        b"\0".join(os.fsencode(argument) for argument in command) + b"\0"
    )


if __name__ == "__main__":
    main()
