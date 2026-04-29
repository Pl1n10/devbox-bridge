# devbox-bridge

MCP server custom che gira sulla devbox e si espone via Cloudflare Tunnel come custom connector su claude.ai.

Espone tool sicuri su filesystem, git, esecuzione test/lint/build e introspezione di sistema, con auth bearer + rate limit + audit log.

> Status: step 7 completato. Il server FastMCP parte su HTTP `/mcp` e registra
> i tool filesystem. Git, execution, system, deploy finale e documentazione
> completa restano negli step successivi.

## Quick start (dev locale)

```bash
python3.12 -m venv .venv
source .venv/bin/activate
pip install -r requirements.lock      # versioni pinned, build riproducibile
pip install -e . --no-deps
pre-commit install                    # opzionale ma consigliato
cp config.yaml.example config.yaml
# edita config.yaml e abilita i progetti che vuoi esporre
pytest
python -m devbox_bridge.server
```

Config runtime:

- default config: `./config.yaml`
- override: `DEVBOX_BRIDGE_CONFIG=/path/to/config.yaml`
- endpoint MCP locale: `http://127.0.0.1:8765/mcp`
- auth: header `Authorization: Bearer <token>`

## Struttura

```
src/devbox_bridge/    # codice sorgente
tests/                # pytest, target coverage 90% su security/auth
deploy/               # systemd unit, docker-compose, cloudflared config, installer
docs/                 # SETUP / SECURITY / TOOLS
```

## Stato implementazione

- Completati: config, auth/rate limit, path/env/command security, audit log,
  tool filesystem, server FastMCP HTTP.
- Pending: tool git, tool execution, tool system, deploy definitivo, docs finali.

## Deploy

Vedi `docs/SETUP.md`.
