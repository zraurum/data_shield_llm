#!/usr/bin/env bash
# ============================================================
# DataShield LLM Service — APISIX Initialization Script
#
# Configures APISIX via the Admin API:
#   1. Upstream → LiteLLM proxy
#   2. Routes   → /v1/chat/completions, /v1/models, /v1/embeddings, /v1/completions
#   3. Global plugin config → rate limiting defaults
#   4. Consumer → default Cursor API key with key-auth + rate limit
#
# Usage:
#   # From the project root after services are healthy:
#   docker compose run --rm -e APISIX_ADMIN_KEY="${APISIX_ADMIN_KEY}" \
#                            -e CURSOR_API_KEY="${CURSOR_API_KEY}" \
#                            -e LITELLM_MASTER_KEY="${LITELLM_MASTER_KEY}" \
#       apisix /bin/bash /scripts/init-apisix.sh
#
#   # Or directly if APISIX is accessible from the host:
#   APISIX_HOST=localhost bash scripts/init-apisix.sh
#
# Environment variables:
#   APISIX_HOST          APISIX host (default: apisix)
#   APISIX_PORT          Admin API port (default: 9180)
#   APISIX_ADMIN_KEY     Admin key from config/apisix/config.yaml
#   LITELLM_HOST         LiteLLM host inside Docker network (default: litellm)
#   LITELLM_PORT         LiteLLM port (default: 4000)
#   LITELLM_MASTER_KEY   LiteLLM master key injected as Authorization header
#   CURSOR_API_KEY       Bearer token for the default Cursor consumer
# ============================================================

set -euo pipefail

APISIX_HOST="${APISIX_HOST:-apisix}"
APISIX_PORT="${APISIX_PORT:-9180}"
APISIX_ADMIN_KEY="${APISIX_ADMIN_KEY:-edd1c9f034335f136f87ad84b625c8f1}"
LITELLM_HOST="${LITELLM_HOST:-litellm}"
LITELLM_PORT="${LITELLM_PORT:-4000}"
LITELLM_MASTER_KEY="${LITELLM_MASTER_KEY:-sk-datashield-master-changeme}"
CURSOR_API_KEY="${CURSOR_API_KEY:-sk-cursor-user1-changeme}"

ADMIN_URL="http://${APISIX_HOST}:${APISIX_PORT}/apisix/admin"
AUTH_HEADER="X-API-KEY: ${APISIX_ADMIN_KEY}"

log() { echo "[$(date -u +%H:%M:%S)] $*"; }
ok()  { echo "[$(date -u +%H:%M:%S)] ✓ $*"; }
err() { echo "[$(date -u +%H:%M:%S)] ✗ $*" >&2; exit 1; }

# ── Wait for APISIX Admin API ────────────────────────────────

log "Waiting for APISIX Admin API at ${ADMIN_URL} ..."
for i in $(seq 1 30); do
    if curl -sf -H "${AUTH_HEADER}" "${ADMIN_URL}/routes" > /dev/null 2>&1; then
        ok "APISIX is ready."
        break
    fi
    echo "  attempt $i/30 — sleeping 3s"
    sleep 3
done

# ────────────────────────────────────────────────────────────
# 1. Upstream — LiteLLM proxy (not exposed to host)
# ────────────────────────────────────────────────────────────

log "Creating upstream: litellm-upstream → ${LITELLM_HOST}:${LITELLM_PORT}"

curl -sf -X PUT "${ADMIN_URL}/upstreams/litellm-upstream" \
    -H "${AUTH_HEADER}" \
    -H "Content-Type: application/json" \
    -d "{
  \"id\": \"litellm-upstream\",
  \"name\": \"LiteLLM Proxy\",
  \"type\": \"roundrobin\",
  \"nodes\": {
    \"${LITELLM_HOST}:${LITELLM_PORT}\": 1
  },
  \"scheme\": \"http\",
  \"pass_host\": \"pass\",
  \"keepalive_pool\": {
    \"size\": 30,
    \"idle_timeout\": 60,
    \"requests\": 1000
  },
  \"timeout\": {
    \"connect\": 10,
    \"send\": 300,
    \"read\": 300
  }
}" > /tmp/apisix_upstream_resp.json

UPSTREAM_ID="$(jq -r '.value.id // .node.value.id // "created"' /tmp/apisix_upstream_resp.json)"
ok "upstream ${UPSTREAM_ID} registered"

# ────────────────────────────────────────────────────────────
# 2. Routes
#
# All routes:
#   - Require Bearer token via key-auth (reads Authorization header)
#   - Rewrite Authorization to inject LITELLM_MASTER_KEY downstream
#   - Add X-Request-ID for tracing
#   - proxy_buffering: off — critical for Cursor SSE streaming
# ────────────────────────────────────────────────────────────

create_route() {
    local route_id="$1"
    local route_name="$2"
    local uri_pattern="$3"
    local methods="$4"

    log "Creating route: ${route_name} (${uri_pattern})"

    curl -sf -X PUT "${ADMIN_URL}/routes/${route_id}" \
        -H "${AUTH_HEADER}" \
        -H "Content-Type: application/json" \
        -d "{
  \"id\": \"${route_id}\",
  \"name\": \"${route_name}\",
  \"uri\": \"${uri_pattern}\",
  \"methods\": ${methods},
  \"upstream_id\": \"litellm-upstream\",
  \"plugins\": {
    \"key-auth\": {
      \"header\": \"Authorization\",
      \"query\": \"api_key\",
      \"hide_credentials\": true
    },
    \"proxy-rewrite\": {
      \"headers\": {
        \"set\": {
          \"Authorization\": \"Bearer ${LITELLM_MASTER_KEY}\"
        }
      }
    },
    \"request-id\": {
      \"include_in_response\": true,
      \"header_name\": \"X-Request-ID\"
    },
    \"limit-req\": {
      \"rate\": 20,
      \"burst\": 10,
      \"key_type\": \"var\",
      \"key\": \"consumer_name\",
      \"rejected_code\": 429,
      \"rejected_msg\": \"{\\\"error\\\":{\\\"message\\\":\\\"Rate limit exceeded\\\",\\\"type\\\":\\\"rate_limit_error\\\",\\\"code\\\":429}}\"
    },
    \"prometheus\": {
      \"prefer_name\": true
    }
  }
}" > /tmp/apisix_route_resp.json

    local created_route_id
    created_route_id="$(jq -r '.value.id // .node.value.id // "created"' /tmp/apisix_route_resp.json)"
    ok "route ${created_route_id} registered"
}

# Chat completions — primary Cursor endpoint (SSE streaming)
create_route "chat-completions" \
    "Chat Completions" \
    "/v1/chat/completions" \
    "[\"POST\"]"

# Models list — Cursor uses this to enumerate available models
create_route "models-list" \
    "Models List" \
    "/v1/models" \
    "[\"GET\"]"

# Embeddings
create_route "embeddings" \
    "Embeddings" \
    "/v1/embeddings" \
    "[\"POST\"]"

# Legacy completions (non-chat)
create_route "completions" \
    "Completions" \
    "/v1/completions" \
    "[\"POST\"]"

# ────────────────────────────────────────────────────────────
# 3. Consumer — default Cursor user
#
# The key value must be: "Bearer <CURSOR_API_KEY>"
# because Cursor sends: Authorization: Bearer sk-cursor-...
# and APISIX key-auth strips the "Bearer " prefix automatically
# when reading the Authorization header.
# ────────────────────────────────────────────────────────────

log "Creating consumer: cursor_default"

curl -sf -X PUT "${ADMIN_URL}/consumers/cursor_default" \
    -H "${AUTH_HEADER}" \
    -H "Content-Type: application/json" \
    -d "{
  \"username\": \"cursor_default\",
  \"desc\": \"Default Cursor IDE consumer\",
  \"plugins\": {
    \"key-auth\": {
      \"key\": \"Bearer ${CURSOR_API_KEY}\"
    }
  }
}" > /tmp/apisix_consumer_resp.json

CONSUMER_USERNAME="$(jq -r '.value.username // .node.value.username // "created"' /tmp/apisix_consumer_resp.json)"
ok "consumer ${CONSUMER_USERNAME} registered"

# ────────────────────────────────────────────────────────────
# 4. Verify
# ────────────────────────────────────────────────────────────

log "Verifying configuration..."

ROUTE_COUNT=$(curl -sf -H "${AUTH_HEADER}" "${ADMIN_URL}/routes" | jq '.total // (.list | length) // 0' 2>/dev/null || echo 0)
CONSUMER_COUNT=$(curl -sf -H "${AUTH_HEADER}" "${ADMIN_URL}/consumers" | jq '.total // (.list | length) // 0' 2>/dev/null || echo 0)

ok "APISIX configured: ${ROUTE_COUNT} route(s), ${CONSUMER_COUNT} consumer(s)"

echo ""
echo "══════════════════════════════════════════════════"
echo "  DataShield APISIX initialization complete."
echo ""
echo "  Cursor settings:"
echo "    OpenAI Base URL : http://localhost:9080"
echo "    API Key         : ${CURSOR_API_KEY}"
echo ""
echo "  To add a new user/developer, run:"
echo "    CURSOR_API_KEY=sk-new-user-key \\"
echo "    bash scripts/add-consumer.sh <username>"
echo "══════════════════════════════════════════════════"
