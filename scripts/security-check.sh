#!/usr/bin/env bash
set -euo pipefail

trap 'rm -f sbom.json' EXIT

cargo fmt --all --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
cargo audit
cargo deny check advisories bans sources licenses
cargo cyclonedx --format json --override-filename sbom
