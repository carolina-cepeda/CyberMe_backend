#!/usr/bin/env bash
# Scan the backend code against the local SonarQube instance using Docker.
#
# Prerequisites:
#   1. docker compose up -d   (from the project root)
#   2. Wait ~60 s for SonarQube to boot (check http://localhost:9000)
#
# Usage:
#   export SONAR_TOKEN=<your-token>
#   ./scripts/sonar-scan-local.sh

set -euo pipefail

SONAR_HOST="${SONAR_HOST:-http://localhost:9000}"
SONAR_TOKEN="${SONAR_TOKEN:?Set SONAR_TOKEN first}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND_DIR="$(dirname "$SCRIPT_DIR")"

echo "Using sonar-scanner via Docker"
echo "SonarQube host:     $SONAR_HOST"
echo "Project:            cyberme-backend"
echo ""

docker run --rm \
  --network host \
  -v "$BACKEND_DIR":/usr/src \
  sonarsource/sonar-scanner-cli:latest \
  -Dsonar.host.url="$SONAR_HOST" \
  -Dsonar.login="$SONAR_TOKEN"

echo ""
echo "Analysis complete. View results at: $SONAR_HOST/dashboard?id=cyberme-backend"
