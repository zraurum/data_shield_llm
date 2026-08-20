# DataShield LLM

Self-hosted LLM gateway with multi-layer guardrails for IDE clients such as Cursor.

Traffic path:

```text
Cursor → APISIX (:9080) → LiteLLM → LLM provider
                 ↓
         Guardrails · Presidio · Ollama · Prometheus · Grafana
```

## Features

- Single external entry point (APISIX) with API-key auth and rate limits
- LiteLLM proxy for OpenAI-compatible model routing
- Guardrails pipeline:
  1. Presidio — PII detection (logging-only by default for coding context)
  2. Regex prompt-injection guard
  3. LLaMA Guard — semantic prompt safety
  4. LiteLLM content filter — malicious code patterns in responses
  5. Semantic guard — optional / currently disabled
  6. LLaMA Guard — semantic response safety
- Observability: Prometheus + Grafana dashboard
- Docker Compose deployment

## Quick start

```bash
cp .env.example .env
# fill OPENROUTER_API_KEY (or your provider key) and rotate secrets

docker compose up -d --build
bash scripts/init-apisix.sh
bash scripts/pull-ollama-models.sh
```

Health checks:

```bash
curl -s http://localhost:9080/v1/models \
  -H "Authorization: Bearer $CURSOR_API_KEY"
```

## Cursor setup

| Setting | Value |
|---|---|
| OpenAI Base URL | `http://localhost:9080/v1` (or a public tunnel URL ending with `/v1`) |
| API Key | `CURSOR_API_KEY` from `.env` |
| Model | Add a custom model that exists in `/v1/models` (e.g. `gpt-4o-mini`) |

Notes:

- Cursor cloud agents cannot call `localhost`. Use a tunnel (`ngrok` / `cloudflared`) for remote agent traffic.
- Built-in Cursor models (`Auto`, `Composer`, etc.) do **not** go through this gateway. Select the custom model you added.

## Useful endpoints

| Service | URL |
|---|---|
| API gateway | http://localhost:9080 |
| Grafana | http://localhost:3000 |
| Prometheus | http://localhost:9090 |

Default Grafana login comes from `.env` (`GRAFANA_ADMIN_USER` / `GRAFANA_ADMIN_PASSWORD`).

## Configuration

- `config/litellm/config.yaml` — models and guardrails
- `config/apisix/config.yaml` — gateway
- `config/guardrails/` — Guardrails AI server config
- `.env.example` — environment variables template

## Repository

https://github.com/zraurum/data_shield_llm

## Authors

- [zraurum](https://github.com/zraurum)
- Nikolai Abramov (`cunick@gmail.com`)
