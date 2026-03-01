#!/bin/bash
# Scan the Docker image for HIGH and CRITICAL vulnerabilities using Trivy.
# Usage: ./scripts/scan-image.sh [image_name]
#
# Requires: trivy (https://aquasecurity.github.io/trivy/)
#   Install: curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

set -euo pipefail

IMAGE="${1:-remote-signer:latest}"

if ! command -v trivy &>/dev/null; then
  echo "ERROR: trivy is not installed. See https://aquasecurity.github.io/trivy/" >&2
  exit 1
fi

echo "Scanning image: ${IMAGE}"
trivy image --severity HIGH,CRITICAL "${IMAGE}"
