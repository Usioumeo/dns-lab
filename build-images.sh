#!/usr/bin/env sh
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Build once: common runtime layer shared by bind4 and bind9.
docker build -t dns-lab-runtime:latest "${ROOT_DIR}/base-runtime"

# Build protocol-specific images reusing the runtime image as final stage base.
docker build -t bind4:latest "${ROOT_DIR}/bind4"
docker build -t bind9:latest "${ROOT_DIR}/bind9"

echo "Built images: dns-lab-runtime:latest, bind4:latest, bind9:latest"
