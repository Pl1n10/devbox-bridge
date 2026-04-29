# HANDOFF.md — devbox-bridge

Stato al **2026-04-29**.

## Stato git

- **Branch:** `main`
- **Ultimo commit:** step 6 (`tools/filesystem.py`) — vedi `git log --oneline -n 1` per l'hash effettivo.
- **Working tree:** clean.

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
- **`<hash-step6>`** — step 6: `tools/filesystem.py` (read/write/patch/list/search). 6 tool con security path-validation + binary/UTF-8 strict + ripgrep wrapper + glob anti-traversal + write enforcement preventivo. 38 test, coverage 90%. ProjectConfig esteso con `max_read_bytes` (ceiling 50 MB). Branch difensivi non testati documentati in `FAILURES.md`.

## Step in corso

**Step 7 — `src/devbox_bridge/server.py` skeleton funzionante.** ⚠️ Review puntigliosa: è il punto in cui auth + rate limit + audit + paths + i tool del filesystem convergono su FastMCP.

Note di integrazione già scritte come docstring in `src/devbox_bridge/server.py`:
- `AuthFailed` → 401 generico (`"unauthorized"`), NIENTE `reason` esposto al client (resta solo nei log).
- `RateLimitExceeded` → 429 + header `Retry-After: 60`.
- `client_ip`: prima `X-Forwarded-For` (primo elemento `ip1, ip2, ip3` — Cloudflare Tunnel passa l'IP originale lì), fallback `request.client.host`, validazione con `ipaddress.ip_address()` (fallita → log `client_ip="(invalid)"` ma proseguo).

**Mapping eccezioni filesystem → audit (da implementare nel server):**
```
PathSecurityError, GlobSecurityError, WriteNotAllowedError → outcome="denied", event="path.rejected"
FileNotFoundError, IsADirectoryError, NotADirectoryError,
  BinaryFileError, FileTooLargeError, UnicodeDecodeError,
  ValueError, RipgrepNotFoundError                          → outcome="error"
success                                                       → outcome="success", event="tool.<name>"
```

`tool.read_file`, `tool.list_*`, `tool.search_files` sono in `AUDITED_READ_EVENTS` → loggati solo se `audit.audit_reads=true`. `tool.write_file`, `tool.apply_patch` sono in `AUDITED_WRITE_EVENTS` → SEMPRE auditati.

### Cosa fare alla ripresa (step 7)

1. Leggere fino in fondo questa sezione + sezione "Decisioni di design non ovvie" sotto.
2. Aggiungere `fastmcp` a `pyproject.toml` (verificare versione disponibile su PyPI).
3. Implementare `server.py`: istanziare FastMCP, registrare i 6 tool del filesystem con i decoratori `@mcp.tool()`, applicare middleware auth + rate limit, esporre HTTP/SSE su `config.server.bind`.
4. Map eccezioni → HTTP codes come da tabella sopra.
5. Inietttare `AuditLogger` nei tool wrapper (i tool puri in `tools/filesystem.py` NON loggano: lo fa il server).
6. Diff preview a utente PRIMA del commit (workflow concordato per server).
7. Test integrazione su `tests/test_server.py` (nuovo): client HTTP fittizio (httpx) che chiama un tool, verifica auth, rate limit, audit log emesso.
8. Aggiornare HANDOFF spostando step 7 in completati e mettendo step 8 in corso.

## Step pending (in ordine)

- **step 8** — `tools/git.py`. Placeholder skipped a `tests/test_tools_git.py:18`. ⚠️ `git_push` deve verificare `project.allow_push` e fail-fast se False.
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

Atteso allo stato attuale (post step 6): `225 passed, 1 skipped` (lo skip è il placeholder di `tests/test_tools_git.py:18` per step 8). Coverage `tools/filesystem.py`: **90%** (le 19 righe scoperte sono branch difensivi, motivazione in `FAILURES.md`).

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
