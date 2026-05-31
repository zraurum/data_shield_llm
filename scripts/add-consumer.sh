#!/usr/bin/env bash
# ============================================================
# DataShield — Add a new Cursor consumer (API key)
#
# Usage:
#   CURSOR_API_KEY=sk-team-backend bash scripts/add-consumer.sh team-backend
#   CURSOR_API_KEY=sk-dev-alice    bash scripts/add-consumer.sh alice
# ============================================================

set -euo pipefail

USERNAME="${1:?Usage: $0 <consumer-username>}"
CURSOR_API_KEY="${CURSOR_API_KEY:?Set CURSOR_API_KEY env var first}"

APISIX_HOST="${APISIX_HOST:-localhost}"
APISIX_PORT="${APISIX_PORT:-9180}"
APISIX_ADMIN_KEY="${APISIX_ADMIN_KEY:-edd1c9f034335f136f87ad84b625c8f1}"

ADMIN_URL="http://${APISIX_HOST}:${APISIX_PORT}/apisix/admin"
AUTH_HEADER="X-API-KEY: ${APISIX_ADMIN_KEY}"

curl -sf -X PUT "${ADMIN_URL}/consumers/${USERNAME}" \
    -H "${AUTH_HEADER}" \
    -H "Content-Type: application/json" \
    -d "{
  \"username\": \"${USERNAME}\",
  \"desc\": \"Cursor consumer: ${USERNAME}\",
  \"plugins\": {
    \"key-auth\": {
      \"key\": \"${CURSOR_API_KEY}\"
    },
    \"limit-count\": {
      \"count\": 1000,
      \"time_window\": 3600,
      \"key_type\": \"consumer\",
      \"rejected_code\": 429,
      \"policy\": \"local\"
    }
  }
}" | jq .

echo ""
echo "Consumer '${USERNAME}' created."
echo "Cursor API Key: ${CURSOR_API_KEY}"
