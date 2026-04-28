# CLAUDE.md — devbox-bridge (locale al repo)

> Questo file è per Claude Code che lavora SU questo repo.
> Non confondere con `~/.claude/CLAUDE.md` (global context Roberto).

## Cosa è questo progetto

MCP server FastMCP esposto via HTTP/SSE (NON stdio). Scopo: dare a claude.ai
accesso controllato a filesystem, git ed esecuzione test/build sulla devbox.

Brief originale completo: `dexbox-bridge.md` nella root.

## Convenzioni

- Python 3.11+, type hints ovunque. La devbox ha solo Python 3.12.3 — il venv viene creato con `python3.12 -m venv .venv`.
- `subprocess.run` con lista args, mai `shell=True`.
- Path sempre validati via `security/paths.py`.
- Comandi sempre validati via `security/commands.py`.
- Logging structured JSON.
- Test pytest, target coverage 90% su `security/` e `auth.py`.

## Dependency management & lockfile

- **Versioni pinned esatte** (`==X.Y.Z`) in `pyproject.toml` per build riproducibili.
- **Lockfile transitivo:** `requirements.lock` generato da `pip freeze --exclude-editable`
  dopo `pip install -e '.[dev]'`. Scelta di `requirements.lock` (vs `uv.lock`) perché
  sulla devbox sono disponibili solo `python3.12` e `pip`; nessun tool extra richiesto.
- **Aggiornare il lock:**
  ```bash
  source .venv/bin/activate
  pip install -e '.[dev]' --upgrade
  pip freeze --exclude-editable > requirements.lock
  ```
- **Reinstall pulito da lock** (quello che farà il deploy):
  ```bash
  pip install -r requirements.lock
  pip install -e . --no-deps
  ```

## Come aggiungere un nuovo tool

1. Implementa la funzione in `src/devbox_bridge/tools/<area>.py`
2. Registrala in `server.py` con il decoratore `@mcp.tool()`
3. Se è un'azione write, audit-loggala via `audit.log_action(...)`
4. Aggiungi test in `tests/test_tools_<area>.py`
5. Documenta in `docs/TOOLS.md`

## Test

```bash
pytest                       # tutti
pytest tests/test_auth.py    # singolo file
pytest --cov=devbox_bridge   # con coverage
```

## Release

TBD — per ora si deploya da source via `deploy/install.sh`.
