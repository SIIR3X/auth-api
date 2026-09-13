#!/usr/bin/env bash
# Refresh every pinned image reference (`name:tag@sha256:...`) in the Dockerfiles
# and compose files to the digest its tag points at today.
#
# A digest cannot be repointed, which is why images are pinned by it; the other
# side is that a pinned image never receives security fixes. Run this before a
# release (or monthly), then rebuild, scan with Trivy and commit the new pins.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"

FILES=(Dockerfile Dockerfile.dev docker-compose.api.yml docker-compose.dev.yml docker-compose.test.yml)
for file in "${FILES[@]}"; do
    refs=$(grep -oE '[a-z0-9./_-]+:[A-Za-z0-9._-]+@sha256:[a-f0-9]{64}' "$file" | sort -u || true)
    for ref in $refs; do
        image=${ref%@*}
        old=${ref#*@}
        new=$(docker buildx imagetools inspect "$image" --format '{{.Manifest.Digest}}')
        if [[ "$new" != sha256:* ]]; then
            echo "ERROR: cannot resolve $image" >&2
            exit 1
        fi
        if [[ "$new" == "$old" ]]; then
            echo "$file: $image up to date"
        else
            sed -i "s|${image}@${old}|${image}@${new}|g" "$file"
            echo "$file: $image ${old:7:12} -> ${new:7:12}"
        fi
    done
done
