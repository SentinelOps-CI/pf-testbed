#!/usr/bin/env python3
"""Validate that CI-referenced commands and files exist."""

from __future__ import annotations

import json
import pathlib
import re
import sys
from typing import Iterable


ROOT = pathlib.Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
PACKAGE_JSON = ROOT / "package.json"
MAKEFILE = ROOT / "Makefile"


def read_package_scripts() -> set[str]:
    package = json.loads(PACKAGE_JSON.read_text(encoding="utf-8"))
    return set(package.get("scripts", {}).keys())


def read_make_targets() -> set[str]:
    target_regex = re.compile(r"^([a-zA-Z0-9_.-]+):(?:\s|$)")
    targets: set[str] = set()
    for line in MAKEFILE.read_text(encoding="utf-8").splitlines():
        match = target_regex.match(line.strip())
        if match and not match.group(1).startswith("."):
            targets.add(match.group(1))
    return targets


def workflow_files() -> Iterable[pathlib.Path]:
    canonical = {"ci.yml", "ci.yaml", "ci-cd.yml", "verify.yml"}
    for name in canonical:
        path = WORKFLOWS / name
        if path.exists():
            yield path


def main() -> int:
    scripts = read_package_scripts()
    make_targets = read_make_targets()
    errors: list[str] = []

    npm_run_regex = re.compile(r"\bnpm run ([a-zA-Z0-9:_-]+)")
    make_regex = re.compile(r"\bmake ([a-zA-Z0-9_.-]+)")
    python_file_regex = re.compile(r"\bpython(?:3)? ([^ \n]+\.py)")

    for workflow in workflow_files():
        content = workflow.read_text(encoding="utf-8")
        for script in npm_run_regex.findall(content):
            if script not in scripts:
                errors.append(f"{workflow}: missing npm script '{script}'")

        for target in make_regex.findall(content):
            if target not in make_targets:
                errors.append(f"{workflow}: missing make target '{target}'")

        for rel_path in python_file_regex.findall(content):
            if rel_path.startswith("-m"):
                continue
            if not (ROOT / rel_path).exists():
                errors.append(f"{workflow}: missing python file '{rel_path}'")

    if errors:
        print("Workflow reference validation failed:")
        for error in errors:
            print(f" - {error}")
        return 1

    print("Workflow reference validation passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
