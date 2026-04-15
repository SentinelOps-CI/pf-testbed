#!/usr/bin/env python3
"""Validate retrieval contract compatibility.

Checks TypeScript and Rust retrieval gateways for shared contract markers.
"""

from __future__ import annotations

import pathlib
import sys


ROOT = pathlib.Path(__file__).resolve().parents[1]
TS_GATEWAY = (
    ROOT / "testbed" / "runtime" / "retrieval-gateway" / "src" / "gateway.ts"
)
RUST_GATEWAY = ROOT / "runtime" / "retrieval-gateway" / "src" / "gateway.rs"


def require(
    text: str, needle: str, source: pathlib.Path, errors: list[str]
) -> None:
    if needle not in text:
        errors.append(f"{source}: missing required contract marker '{needle}'")


def main() -> int:
    ts = TS_GATEWAY.read_text(encoding="utf-8")
    rust = RUST_GATEWAY.read_text(encoding="utf-8")
    errors: list[str] = []

    markers = ["tenant", "subject", "shard", "query_hash", "result_hash", "nonce"]
    for marker in markers:
        require(ts, marker, TS_GATEWAY, errors)
        require(rust, marker, RUST_GATEWAY, errors)

    # Canonical contract fields for receipt expiry and signature.
    require(ts, "exp", TS_GATEWAY, errors)
    require(ts, "sig", TS_GATEWAY, errors)
    require(rust, "exp", RUST_GATEWAY, errors)
    require(rust, "sig", RUST_GATEWAY, errors)

    if errors:
        print("Retrieval contract check failed:")
        for error in errors:
            print(f" - {error}")
        return 1

    print("Retrieval contract check passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
