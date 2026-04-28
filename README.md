# devbox-bridge

MCP server custom che gira sulla devbox e si espone via Cloudflare Tunnel come custom connector su claude.ai.

Espone tool sicuri su filesystem, git, esecuzione test/lint/build e introspezione di sistema, con auth bearer + rate limit + audit log.

> Status: skeleton iniziale. Implementazione in corso secondo il brief in `docs/devbox-bridge-brief.md`.

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

## Struttura

```
src/devbox_bridge/    # codice sorgente
tests/                # pytest, target coverage 90% su security/auth
deploy/               # systemd unit, docker-compose, cloudflared config, installer
docs/                 # SETUP / SECURITY / TOOLS
```

## Deploy

Vedi `docs/SETUP.md`.
