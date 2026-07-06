# devbox-bridge

MCP server custom che gira sulla devbox e si espone via Cloudflare
Tunnel come custom connector su claude.ai.

Espone **27 tool sicuri** su filesystem, git, esecuzione test/lint/build,
introspezione di sistema (info host, log, journalctl) e vault di note
markdown (Mnemosyne), con auth bearer + rate limit + audit log.

> Status: **step 1-13 completati**. Server FastMCP HTTP `/mcp`
> con 27 tool registrati, auth+rate limit, audit log strutturato,
> deploy hardened (systemd + ACL chirurgiche). Suite: 400 test verdi.

## Tool esposti

- **Filesystem (6):** `list_projects`, `read_file`, `write_file`,
  `apply_patch`, `list_directory`, `search_files`.
- **Git (7):** `git_status`, `git_diff`, `git_log`, `git_branch_current`,
  `git_create_branch`, `git_commit`, `git_push`.
- **Esecuzione (4):** `run_command`, `run_tests`, `run_lint`, `run_build`.
- **Sistema (4, read-only):** `get_system_info`, `list_systemd_services`,
  `tail_log`, `read_journalctl`.
- **Notes (6):** `notes_list`, `notes_read`, `notes_search`,
  `notes_write`, `notes_sync_pull`, `notes_sync_status` — vault Mnemosyne
  (`~/notes`, repo git con origin sul Gitea della VM `mnemosyne`).
  Scrittura solo sotto `llm/` e `inbox/`, pull-prima-di-scrivere, un
  commit per nota, mai force-push, nessuna delete. Config via env:
  `NOTES_ROOT`, `NOTES_WRITE_DIRS`, `NOTES_MAX_READ_BYTES`. Setup
  produzione: `deploy/setup-notes-access.sh` (ACL, deploy key, drop-in
  systemd).

Reference completo: [`docs/TOOLS.md`](docs/TOOLS.md).

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
deploy/               # systemd unit, drop-in, installer, docker-compose, cloudflared snippet
docs/                 # SETUP / SECURITY / TOOLS / brief originale
```

## Stato implementazione

| Step | Componente | Stato |
|------|-----------|-------|
| 1 | Skeleton repo | ✅ |
| 2 | `config.py` | ✅ |
| 3 | `auth.py` (bearer + rate limit) | ✅ |
| 4 | `security/{paths,commands,env}.py` | ✅ |
| 5 | `audit.py` (JSON Lines + rotation) | ✅ |
| 6 | `tools/filesystem.py` | ✅ |
| 7 | `server.py` (FastMCP HTTP + middleware) | ✅ |
| 8 | `tools/git.py` (read+write + backstop) | ✅ |
| 9 | `tools/execution.py` | ✅ |
| 10 | `tools/system.py` | ✅ |
| 11 | `deploy/*` (systemd + ACL + cloudflared) | ✅ |
| 12 | Documentazione finale | ✅ |
| 13 | `tools/notes.py` (vault Mnemosyne) | ✅ |

## Deploy

Vedi [`docs/SETUP.md`](docs/SETUP.md) per l'installazione end-to-end
(installer idempotente, hardening systemd, ingress cloudflared,
registrazione connector claude.ai).

Per il threat model e la mappa delle difese in serie vedi
[`docs/SECURITY.md`](docs/SECURITY.md).
