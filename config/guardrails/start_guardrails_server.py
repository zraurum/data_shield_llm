"""
Stable Guardrails API launcher.

Why this exists:
- Some Guardrails versions expose a broken `guardrails start` CLI path where
  Typer OptionInfo defaults are passed into runtime code.
- This tiny launcher bypasses that codepath and starts FastAPI directly.
"""

import os

import uvicorn
from guardrails_api.app import create_app


def _as_bool(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes", "on"}


def main() -> None:
    port = int(os.environ.get("GUARDRAILS_PORT", "8000"))
    config_path = os.environ.get("GUARDRAILS_CONFIG", "/app/config.py")
    env_path = os.environ.get("GUARDRAILS_ENV_FILE", "").strip() or None
    env_override = _as_bool(os.environ.get("GUARDRAILS_ENV_OVERRIDE", "false"))

    app = create_app(
        env=env_path,
        config=config_path,
        port=port,
        middleware=None,
        env_override=env_override,
    )
    uvicorn.run(app, host="0.0.0.0", port=port)


if __name__ == "__main__":
    main()
