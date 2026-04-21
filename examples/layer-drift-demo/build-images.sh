#!/usr/bin/env bash

set -euo pipefail

docker build -f Dockerfile.baseline -t layer-drift-demo:baseline .
docker build -f Dockerfile.extra -t layer-drift-demo:extra .
docker build -f Dockerfile.missing -t layer-drift-demo:missing .
docker build -f Dockerfile.reordered -t layer-drift-demo:reordered .
docker build -f Dockerfile.changed -t layer-drift-demo:changed .

printf '\nBuilt demo images:\n'
printf '  %s\n' \
  layer-drift-demo:baseline \
  layer-drift-demo:extra \
  layer-drift-demo:missing \
  layer-drift-demo:reordered \
  layer-drift-demo:changed
