#!/usr/bin/env bash
# ============================================================
# DataShield — Pull required Ollama models
#
# Run once after the first `docker compose up`:
#   bash scripts/pull-ollama-models.sh
#
# Or from inside the project:
#   docker compose exec ollama ollama pull llama-guard3:1b
#   docker compose exec ollama ollama pull nomic-embed-text
# ============================================================

set -euo pipefail

OLLAMA_HOST="${OLLAMA_HOST:-localhost}"
OLLAMA_PORT="${OLLAMA_PORT:-11434}"
OLLAMA_URL="http://${OLLAMA_HOST}:${OLLAMA_PORT}"

VALIDATION_MODEL="${OLLAMA_VALIDATION_MODEL:-llama-guard3:1b}"
EMBED_MODEL="${OLLAMA_EMBED_MODEL:-nomic-embed-text}"

# When LLaMA Guard runs on OpenRouter we don't need the local validation
# model, so we can save ~1 GB of disk + ~10 min of pull time on first run.
LLAMA_GUARD_PROVIDER_NORMALIZED="$(echo "${LLAMA_GUARD_PROVIDER:-}" | tr '[:upper:]' '[:lower:]')"
SKIP_VALIDATION_MODEL=false
if [ "${LLAMA_GUARD_PROVIDER_NORMALIZED}" = "openrouter" ]; then
    SKIP_VALIDATION_MODEL=true
elif [ -z "${LLAMA_GUARD_PROVIDER_NORMALIZED}" ] && [ -n "${OPENROUTER_API_KEY:-}" ]; then
    # Auto-detect: same rule the guardrails server uses internally.
    SKIP_VALIDATION_MODEL=true
fi

log() { echo "[$(date -u +%H:%M:%S)] $*"; }
ok()  { echo "[$(date -u +%H:%M:%S)] ✓ $*"; }

log "Waiting for Ollama at ${OLLAMA_URL} ..."
for i in $(seq 1 20); do
    if curl -sf "${OLLAMA_URL}/api/tags" > /dev/null 2>&1; then
        ok "Ollama is ready."
        break
    fi
    echo "  attempt $i/20 — sleeping 3s"
    sleep 3
done

pull_model() {
    local model="$1"
    log "Pulling model: ${model}"
    curl -sf -X POST "${OLLAMA_URL}/api/pull" \
        -H "Content-Type: application/json" \
        -d "{\"name\": \"${model}\"}" \
        --no-buffer | while IFS= read -r line; do
            status=$(echo "$line" | python3 -c "import sys,json; d=json.loads(sys.stdin.read()); print(d.get('status',''))" 2>/dev/null || true)
            [ -n "$status" ] && echo "  ${status}"
        done
    ok "Model ready: ${model}"
}

if [ "${SKIP_VALIDATION_MODEL}" = "true" ]; then
    log "LLAMA_GUARD_PROVIDER=openrouter detected — skipping ${VALIDATION_MODEL}"
else
    pull_model "${VALIDATION_MODEL}"
fi

pull_model "${EMBED_MODEL}"

echo ""
echo "══════════════════════════════════════════════════"
echo "  Ollama models ready:"
if [ "${SKIP_VALIDATION_MODEL}" = "true" ]; then
    echo "    (skipped) ${VALIDATION_MODEL}  → handled by OpenRouter"
else
    echo "    ${VALIDATION_MODEL}  → prompt + response safety (LLM judge)"
fi
echo "    ${EMBED_MODEL}        → semantic_guard embeddings"
echo ""
echo "  Installed models:"
curl -sf "${OLLAMA_URL}/api/tags" | python3 -c "
import sys, json
tags = json.load(sys.stdin).get('models', [])
for m in tags:
    size_mb = m.get('size', 0) // 1024 // 1024
    print(f'    {m[\"name\"]:40s} {size_mb} MB')
" 2>/dev/null || echo "    (could not list models)"
echo "══════════════════════════════════════════════════"
