#!/usr/bin/env bash
# Builds the package image locally, exactly as CI does: the keys are downloaded from the release
# `keys-21493588` and checked against keys/SHA256SUMS and the key-set fingerprint inside the build.
#
#   ./build.sh                       → solana-proof-server:<VERSION>-21493588 (this machine's platform)
#   ./build.sh --platform linux/amd64
#   TAG=my/name:dev ./build.sh
#
# The base images are pinned by digest and NOT pulled when present locally (--pull=false); pass
# --pull to refresh them. Extra arguments go to `docker build`.
set -euo pipefail
cd "$(dirname "$0")"

VERSION=$(tr -d '[:space:]' < VERSION)
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$ ]] || { echo "VERSION is not a version: $VERSION" >&2; exit 1; }
TAG=${TAG:-solana-proof-server:${VERSION}-21493588}

pull=(--pull=false)
for a in "$@"; do [[ "$a" == --pull || "$a" == --pull=true ]] && pull=(); done

echo "building $TAG (package $VERSION, key set 21493588)"
docker build "${pull[@]}" --build-arg PACKAGE_VERSION="$VERSION" --tag "$TAG" "$@" .
docker image inspect "$TAG" --format 'built {{index .RepoTags 0}}: {{.Size}} bytes ({{.Architecture}})'
