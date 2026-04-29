# HANDOFF.md — devbox-bridge

Stato al **2026-04-29**.

## Stato git

- **Branch:** `main`
- **Ultimo commit:** step 8 (`tools/git.py` + wiring server) — TBD (commit dopo diff preview).
- **Working tree:** modifiche locali step 8 non committate (`src/devbox_bridge/tools/git.py`, `src/devbox_bridge/server.py`, `tests/test_tools_git.py`, `tests/test_server.py`, `tests/conftest.py`, `HANDOFF.md`).

## Step completati

Implementazione segue l'ordine fissato in `docs/devbox-bridge-brief.md:243`:
`config → auth → security/* → audit → tools/filesystem → server skeleton → tools/git → tools/execution → tools/system → deploy → docs`.

- `50bcafa` — step 1: initial skeleton
- `a03db83` — step 2: `config.py` con validation (ProjectName regex, allow_push⇒write_enabled, unique paths, ecc.)
- `738bf79` — step 3: `auth.py` (bearer SHA-256 timing-safe + sliding-window rate limit per token+IP)
- `161e490` — step 4 round A: `security/paths.py` (resolve_within / resolve_project_path) + `security/env.py`
- `75e4cd0` — step 4 round B: `security/commands.py` (tokenize-and-check, whitelist regex)
- `733bcf0` — patch: `/opt` aggiunto ai `_DANGER_PATHS` di `security/commands.py`
- `1793358` — step 5: `audit.py` (logger thread-safe, rotazione+gzip, retention, sanitizzazione `<redacted>` / `<redacted-path>`)
- `a8553a6` — step 6: `tools/filesystem.py` (read/write/patch/list/search). 6 tool con security path-validation + binary/UTF-8 strict + ripgrep wrapper + glob anti-traversal + write enforcement preventivo. 38 test, coverage 90%. ProjectConfig esteso con `max_read_bytes` (ceiling 50 MB). Branch difensivi non testati documentati in `FAILURES.md`.
- `0671182` — step 7: `server.py` FastMCP funzionante per i 6 tool filesystem. Aggiunti middleware bearer auth/rate-limit, mapping 401/429, audit wrapper per success/error/denied, HTTP app su `/mcp`, e `tests/test_server.py` (12 test). Aggiornati README/docs/PM e aggiunto `gpt5.5-part.md` con il dettaglio degli interventi. Verifica locale: `237 passed, 1 skipped`; `mypy src` pulito; `ruff` pulito sui file step 7.
- `TBD` — step 8: `tools/git.py` con 7 tool (4 read + 3 write). `git_status` su porcelain v1 -z, `git_diff` con filtro path validato via `resolve_within`, `git_log` (limit clampato a `MAX_LOG_LIMIT=200`), `git_branch_current` con fallback detached. Write: `git_create_branch` (validazione via `git check-ref-format`), `git_commit` (paths obbligatori, mai `-a`), `git_push` (richiede `allow_push`, no `--force`/`--mirror`/`--delete`/`--prune`/`--force-with-lease`/`--all`). Aggiornato `server.py` per registrare i 7 tool e mappare `PushNotAllowedError` come `outcome="denied"` (event `tool.git_push`). Conftest esteso con `tmp_git_repo`, `tmp_git_repo_with_origin` (bare locale) e fixture `config_git_{ro,rw,push}`. 32 test git + 2 test server. Verifica: `271 passed`; `mypy src` pulito; `ruff` pulito sui file step 8; coverage `tools/git.py` 90%.

## Step in corso

(nessuno — step 8 chiuso, prossimo step 9)

## Step pending (in ordine)

- **step 9** — `tools/execution.py` (run_command, run_tests, run_lint, run_build). Usa `security/commands.py` + `security/env.py` per env sanitizzato (no LD_PRELOAD/LD_LIBRARY_PATH). subprocess con lista args, mai shell=True.
- **step 10** — `tools/system.py` (tail_log, list_systemd_services, get_system_info). Read-only.
- **step 11** — file deploy: `deploy/devbox-bridge.service`, `deploy/docker-compose.yml`, `deploy/cloudflared-config.yml`, `deploy/install.sh`. **NON** systemctl enable/start automatici; **NON** aprire firewall.
- **step 12** — documentazione: aggiornare `README.md`, `docs/SETUP.md`, `docs/SECURITY.md`, `docs/TOOLS.md`.
- **step 13** — riepilogo finale all'utente: cosa fatto, cosa fare manualmente lui, token plain (UNA volta), URL connector `https://mcpdev.robertonovara.me`.

## Decisioni di design non ovvie

Cose che non si capiscono leggendo solo il codice. La motivazione storica importa per giudicare edge case futuri.

- **AuthFailed → 401 con body generico `"unauthorized"`**, NIENTE `reason` esposto al client. Il `reason` resta solo nei log server-side. Concordato durante review step 3. Motivo: niente info disclosure (token unknown vs token expired vs token revoked → tutti uguali per il client).
- **RateLimitExceeded → 429** con header `Retry-After: 60`. Motivo: standard HTTP, permette retry intelligenti dei client.
- **client_ip extraction:** prima `X-Forwarded-For` (primo elemento `ip1, ip2, ip3`) perché Cloudflare Tunnel passa l'IP originale lì; fallback `request.client.host`; sanitizzazione con `ipaddress.ip_address()`, fallita → log `client_ip="(invalid)"` ma proseguo (non blocco la richiesta).
- **Rate limit applicato DOPO auth success.** Motivo: evita DoS-via-spam-token-non-validi che esauriscano il budget di rate limiting di token validi. Token invalidi vanno in `auth.failed` (audited) ma non consumano slot di un altro token.
- **TOCTOU su `resolve_within` esplicitamente accettato.** Motivo: filesystem progetti è single-tenant (utente `hypn0`), nessun altro non-root può creare symlink dentro i progetti, env subprocess sanitizzato (no LD_PRELOAD). Mitigazione completa con `openat()+RESOLVE_BENEATH` non vale la complessità per il threat model attuale. Documentato in `security/paths.py` docstring.
- **`/opt` nei `_DANGER_PATHS` di `security/commands.py`.** Motivo: tipico mount-point per software third-party non gestito da pkgmgr (Oracle, agenti commerciali). Bloccare per default.
- **`audit.audit_reads=False` di default.** Motivo: read frequenti, audit log esploderebbe di rumore. Write e auth-fail SEMPRE auditati anche con flag off.
- **Hashing token con `hashlib.sha256` (no bcrypt/argon2).** Motivo: token è high-entropy random (32+ byte), non password user-chosen → derivazione lenta non aggiunge valore. `hmac.compare_digest` per timing-safe compare. Discussione in step 3.
- **Tokenize-and-check per `command_whitelist`** (non regex match sull'intera stringa). Motivo: prevenire bypass tipo `pytest; rm -rf /` dove il pattern matcha "pytest" ma la stringa contiene injection. Tokenize via `shlex.split` e verifica argv[0] + flag pattern individuali.
- **`requirements.lock` invece di `uv.lock`/`poetry.lock`.** Motivo: devbox ha solo `python3.12` + `pip`, niente tooling extra richiesto per il deploy. `pip freeze --exclude-editable` basta.
- **Python 3.12 fissato** (non 3.11+). Motivo: è quello sulla devbox e basta — niente versioni multiple da supportare.
- **Output filesystem tools ritorna path RELATIVI alla project root.** Motivo: niente info disclosure sulla struttura assoluta del filesystem reale (`/home/hypn0/projects/...`).
- **`max_read_bytes` ceiling 50MB.** Motivo: content torna inline nel JSON response MCP — 100MB saturerebbe context window di qualunque client. Per file più grossi servirebbe un futuro `read_file_chunk(path, offset, size)`.

## Workflow concordato con l'utente

- **Identità git:** `Pl1n10` (utente GitHub Roberto Novara). Commit firmati a nome utente, NON a nome Claude. Mai usare email di servizio.
- **Diff preview obbligatoria** prima del commit per: `auth.py`, `security/*`, `audit.py`, `tools/filesystem.py`, `server.py`. Per altri file: commit a step verde dopo conferma utente.
- **Auto-commit a step verde** consentito SOLO se: tutti i test passano (`.venv/bin/pytest -q`) E ruff non lamenta E mypy pulito E utente ha già visto il diff o l'ha esplicitamente esonerato per quel file.
- **Mai `git push`** automatici. Mai.
- **Mai assumere credenziali** o secrets. Se servono, chiedere all'utente.
- **Aggiornare HANDOFF.md a fine step** (non a fine turno), come parte del commit dello step (un solo commit, codice + handoff allineati).
- **`/opt`, `/etc`, `/var`, `/usr`, `/root`, `/boot`, `/sys`, `/proc`, `/dev`** sono `_DANGER_PATHS`: nessun tool li deve toccare in scrittura.

## Come verificare lo stato verde della suite

```bash
source .venv/bin/activate
pytest -q
```

Atteso allo stato attuale (post step 8): `271 passed` (placeholder skip rimosso, +34 test rispetto allo step 7: 32 git + 2 server).

Per quando aggiungeremo lint/mypy in pipeline:

```bash
.venv/bin/pytest -q && .venv/bin/ruff check src tests && .venv/bin/mypy src
```

Coverage target su `security/` e `auth.py`: 90%.

```bash
.venv/bin/pytest --cov=devbox_bridge --cov-report=term-missing
```

## File da leggere per riprendere il filo (in ordine)

1. `~/.claude/CLAUDE.md` — global context Roberto (auto-caricato).
2. `./CLAUDE.md` — convenzioni locali del repo.
3. `./HANDOFF.md` — questo file.
4. `./docs/devbox-bridge-brief.md:240-265` — workflow originale dell'utente, lista "non fare", chiusura attesa.
5. `git log --oneline -n 10` — ordine effettivo dei commit.
6. `git status` — verifica working tree.
7. `./FAILURES.md` — vuoto al momento; se non lo è più, leggerlo.
8. Solo se si riprende lo step 6: `src/devbox_bridge/security/paths.py`, `src/devbox_bridge/audit.py`, `src/devbox_bridge/config.py` (per capire come si integrano i tool del filesystem).
