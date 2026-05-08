# HANDOFF.md — devbox-bridge

Stato al **2026-05-08**.

## Stato git

- **Branch:** `main`
- **Ultimo commit:** step 13 (post-deploy hardening: ACL parent traversal + `tail_log` ordering) — `ec7b1e7`.
- **Pushato su `origin/main`**.
- **Working tree:** clean.

## Stato deploy (2026-05-08)

Servizio installato e in esecuzione sulla devbox. `install.sh` lanciato
da Claude Code via `sudo` su autorizzazione utente. Configurazione
minimale di partenza: solo `devbox-bridge` stesso come progetto opt-in,
`write_enabled: false`. Smoke test end-to-end verde (vedi sotto).

| Componente | Stato |
|---|---|
| Pacchetto host `acl` | installato (mancante prima del deploy) |
| Utente `devbox-bridge` (no-login, gruppo `systemd-journal`) | creato |
| `/etc/devbox-bridge/{config.yaml,token.sha256}` | preparati, owner corretti, perms 0640 |
| ACL chirurgiche `r-X` su `/home/hypn0/projects/devbox-bridge` | applicate |
| Drop-in systemd `projects.conf` | rigenerato vuoto (zero progetti `write_enabled`) |
| Codice in `/opt/devbox-bridge` | allineato a `e799910` |
| venv + `requirements.lock` + entry point `devbox-bridge` | installati |
| `devbox-bridge.service` | `enabled` + `active (running)` su `127.0.0.1:8765/mcp` |

Smoke test end-to-end (FastMCP client Python locale come
`devbox-bridge`):

- `list_tools` → 21 tool registrati.
- `list_projects` → ritorna `devbox-bridge` read-only.
- `write_file` su progetto `write_enabled=false` → `ToolError:
  WriteNotAllowedError`.
- `curl` con token errato → `HTTP 401 unauthorized` (body generico).
- Audit log `/var/log/devbox-bridge/audit/audit.log` scritto:
  `auth.failed` + `path.rejected` con `token_id` sha256 troncato a
  8 char, `args_summary.content` ridotto a `{bytes, content_sha8}`
  (no plain content).

**Pending lato operatore (rete + claude.ai):**

1. Merge dello snippet `deploy/cloudflared-config.yml` nel `config.yml`
   di `cloudflared`. Nota: `cloudflared` non è installato sulla devbox
   stessa — verifica dove gira il tunnel (`gaia`/`urano`?). Se
   l'origin del tunnel è altrove, il `service:` nello snippet va
   adattato a `http://<devbox-tailscale-ip>:8765` invece di
   `127.0.0.1`.
2. `cloudflared tunnel route dns <TUNNEL> mcpdev.robertonovara.me`
   (solo prima volta).
3. (Raccomandato) Cloudflare Access policy davanti al tunnel.
4. Registrazione connector su claude.ai con URL
   `https://mcpdev.robertonovara.me/mcp` + header bearer.

**Findings post-deploy (audit dal connector claude.ai 2026-05-08):**

L'utente ha eseguito un audit di sicurezza dal connector subito dopo
il deploy iniziale. Riassunto:

- *(false positive)* Path traversal in `read_file`/`list_directory`:
  il client riceveva `EACCES` su `/home/hypn0/projects` invece di
  `PathSecurityError` esplicito. Verificato: il blocco è a livello
  codice (`relative_to` + `resolve(strict=False)`), il sintomo
  EACCES era dovuto al bug perm parent path (vedi step 13). Test
  diretto come `hypn0` con perms ok → `PathSecurityError` per tutti
  i traversal tentati.
- *(bug bloccante)* Service user non poteva attraversare `/home/hypn0`
  (default `0750 hypn0:hypn0`) → tutti i tool filesystem tornavano
  EACCES. Fix step 13: `setfacl -m u:devbox-bridge:--x` sui parent
  path in `install.sh`.
- *(info-leak debole)* `tail_log` con path FUORI whitelist e
  inesistente ritornava `LogPathNotFoundError` ("non esiste") invece
  di `LogPathNotAllowedError` ("non in whitelist"). Discriminava
  l'esistenza di file fuori whitelist. Fix step 13: invertito ordine
  di check in `resolve_within_any` (whitelist PRIMA, esistenza DOPO).
- *(scelta intenzionale)* `list_systemd_services` con `name_filter=""`
  enumera tutte le ~150 service unit del sistema (no whitelist hard).
  Asimmetria con `read_journalctl` voluta (metadati pubblici vs log
  content). Documentata esplicitamente in `SECURITY.md` allo step 13.

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
- `4405a91` — step 8: `tools/git.py` con 7 tool (4 read + 3 write). `git_status` su porcelain v1 -z, `git_diff` con filtro path validato via `resolve_within`, `git_log` (limit clampato a `MAX_LOG_LIMIT=200`), `git_branch_current` con fallback detached. Write: `git_create_branch` (validazione via `git check-ref-format`), `git_commit` (paths obbligatori, mai `-a`), `git_push` (richiede `allow_push`, no `--force`/`--mirror`/`--delete`/`--prune`/`--force-with-lease`/`--all`). Aggiornato `server.py` per registrare i 7 tool e mappare `PushNotAllowedError` come `outcome="denied"` (event `tool.git_push`). Conftest esteso con `tmp_git_repo`, `tmp_git_repo_with_origin` (bare locale) e fixture `config_git_{ro,rw,push}`. 32 test git + 2 test server. Verifica: `271 passed`; `mypy src` pulito; `ruff` pulito sui file step 8; coverage `tools/git.py` 90%.
- `2001a6b` — step 9: `tools/execution.py` con 4 tool (run_command, run_tests, run_lint, run_build). subprocess.run con lista args (mai shell=True), cwd=project_root, env sanitizzato via `security/env.py`, stdin=DEVNULL. Costanti hardcoded e commentate: `MAX_EXEC_TIMEOUT_SECONDS=600` (cap brief), `DEFAULT_RUN_COMMAND_TIMEOUT_SECONDS=60`, `DEFAULT_CONFIGURED_TIMEOUT_SECONDS=300`, `MAX_OUTPUT_BYTES=100KB`. Validazione comando: `run_command` → deny list + whitelist regex (`re.fullmatch`); `run_tests/lint/build` → solo deny list (whitelist bypassata, comandi admin-authorized in config). Esposta nuova `check_deny_list()` pubblica in `security/commands.py` (split esplicito, non side-effect di whitelist vuota). `exit_code != 0` e `timed_out` NON sollevano eccezione (response normale con campi). Tutti e 4 i tool richiedono `write_enabled=true` (fail-secure: pytest scrive `.pytest_cache`, build genera artefatti, lint --fix riscrive). `audit.py` esteso con campo `outcome_detail` opzionale (`completed`/`nonzero_exit`/`timed_out`); il server lo popola solo per i tool exec, no promozione a `outcome="error"`. Server: comando in args_summary troncato a 500 char (`COMMAND_AUDIT_TRUNCATE_CHARS`, anti log-poisoning); stdout/stderr riassunti via `summarize_command_output()`. `CommandRejectedError` mappata come `event="command.rejected"`/`outcome="denied"`. Conftest esteso con parametri `test_command/lint_command/build_command/command_whitelist/env_passthrough` per `_make_config` e `config_factory`. Test: 37 nuovi su `tools/execution.py` (coverage 96%) + 4 nuovi su `server.py` (registrazione tool + audit denied + audit success con `outcome_detail` + truncate command). `tests/test_server.py` ora 18 test. Verifica: `312 passed`; `mypy src` pulito; `ruff` pulito sui file modificati.

- `3f72eff` — step 11: deploy finalizzato. `deploy/install.sh` idempotente root-only: crea utente `devbox-bridge` (no-login), lo aggiunge a `systemd-journal` (NON `adm`); prepara `/etc/devbox-bridge` (root:bridge 0750), `/var/log/devbox-bridge` (bridge:bridge 0750), `/opt/devbox-bridge` (bridge:bridge 0750); copia `config.yaml.example` → `/etc/devbox-bridge/config.yaml` solo se manca; probe ACL via `setfacl`+`getfacl` su `mktemp` (NON grep su mount options — falsi negativi su ext4 dove `acl` non compare in `mount`); parsea `config.yaml` via `python3 -c "import yaml"` (PyYAML), per ogni progetto: rifiuta symlink, `realpath -e`, fail se fuori da `/home/hypn0/projects/`, applica `setfacl -R -m u:bridge:r-X` (read-only) o `rwX` ricorsivo + default ACL (write_enabled); rigenera SEMPRE `/etc/systemd/system/devbox-bridge.service.d/projects.conf` da zero (anche vuoto se zero progetti rw, evita entry stale su downgrade rw→ro); genera token random sha256 in `token.sha256` 0640 root:bridge SOLO se manca, stampa plain UNA volta in stdout; `daemon-reload` ma NO `enable/start` automatici; stampa next steps (clone+venv+pip+systemctl). `deploy/devbox-bridge.service` unit base statica con hardening completo (`NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome=read-only`, `MemoryDenyWriteExecute`, `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6`, `SystemCallFilter=@system-service ~@privileged @resources`, `PrivateTmp/Devices`, `LockPersonality`, `ProtectProc=invisible`, `LimitNOFILE=4096`, `TasksMax=256`); `ReadWritePaths=/var/log/devbox-bridge` di base, i path progetti vengono dal drop-in. `deploy/Dockerfile` `python:3.12-slim` con `git`+`ripgrep`, UID 9876, build da `requirements.lock` + `pip install -e . --no-deps`. `deploy/docker-compose.yml` bind 127.0.0.1:8765, `read_only:true`, `cap_drop:ALL`, `no-new-privileges`, `tmpfs:/tmp`, mount progetti commentati. `deploy/cloudflared-config.yml` snippet ingress de-commentato (header chiarisce: merge nel config esistente, non standalone). `FAILURES.md` esteso con voci 2026-05-04 sulle opzioni scartate (gruppo `hypn0` viola least privilege; servizio come `hypn0` annulla `ProtectHome`). Verifica: `364 passed` (suite Python invariata, step 11 non tocca codice Python); `bash -n deploy/install.sh` clean.

- `30a4889` — step 10: `tools/system.py` con 4 tool read-only (`get_system_info`, `list_systemd_services`, `tail_log`, `read_journalctl`). Aggiunto `SystemConfig` opzionale a `AppConfig` con default permissivi (`/var/log/devbox-bridge`, `devbox-bridge.service`, filter `devbox-`); single source of truth in `config.py` (`DEFAULT_LOG_PATHS_WHITELIST`/`DEFAULT_SYSTEMD_UNIT_WHITELIST`/`DEFAULT_SYSTEMD_FILTER`). Semantica fail-secure: sezione `system:` omessa → default permissivo; whitelist esplicitamente `[]` → zero risorse accessibili. Costanti commentate: `SYSTEM_TIMEOUT_SECONDS=30`, `DEFAULT_LOG_LINES=100`, `MAX_LOG_LINES=5000`, `MAX_LOG_OUTPUT_BYTES=512KB` (metà context window 200K-token). Path validation via nuova `security.paths.resolve_within_any(candidate, allowed_roots)`: candidato `Path.resolve(strict=True)` PRIMA del confronto → symlink in whitelist che escono fuori sono rifiutati; ordine root non significativo; root inesistenti saltati. Unit validation via doppio gate (regex stretta `^[A-Za-z0-9._@:-]{1,64}$` + appartenenza a whitelist). Filter `list_systemd_services` validato con stessa regex (defense-in-depth contro injection nonostante `shell=False`). `get_system_info` resiliente a fallimenti parziali (df/uname assenti → campo a default, no eccezione). Schema: `uptime_seconds: int`, `memory_bytes` in byte (kB×1024), `disk[]` human-readable da `df -h` (NON parsare numericamente). `audit.py` esteso: outcome `denied`/`error` SEMPRE auditato (ignora `should_audit`/`audit_reads`) — denial è materiale forense. Server: `LogPathNotAllowedError` mappata a `event="path.rejected"`/`outcome="denied"` (simmetrica a `WriteNotAllowedError`); `JournalctlUnitNotAllowedError` come `tool.read_journalctl`/`denied`. 4 tool registrati in `create_mcp`. Permessi journal: utente in gruppo `adm` (Ubuntu default) o `systemd-journal` sufficiente. Modello PII single-tenant documentato. Test: 7 nuovi `resolve_within_any` in `tests/test_path_safety.py`, 42 nuovi in `tests/test_tools_system.py` (coverage `tools/system.py` 93%, target ≥90%; 10 righe scoperte = branch difensivi `/proc` read failures), 3 nuovi in `tests/test_server.py` (registrazione 4 tool + audit denied + audit success non auditato). Verifica: `364 passed`; `mypy src` pulito; `ruff check` clean.

## Step completati (segue)

- `ee45247` — step 12: documentazione finale.
  - `docs/TOOLS.md` polish: sostituiti riferimenti `file:line` con simboli (`MCP_HTTP_PATH`, `SKIP_DIRS`, `_REMOTE_NAME_RE`, `_FORBIDDEN_PUSH_FLAGS`, `COMMAND_AUDIT_TRUNCATE_CHARS`); chiarita semantica `git_log` `limit` (`< 1` → `ValueError`; `> MAX_LOG_LIMIT` → clamp silenzioso `min`); rimosso aggettivo "atomico" da `apply_patch` con nota esplicita "non atomico a livello filesystem, verificabile via `content_sha8_after`"; sostituito `devbox-bridge-brief.md:55` con riferimento simbolico alla sezione "Git" del piano tool.
  - `docs/SECURITY.md` aggiornato: banner `step 10` → `MVP (1-12 chiusi)`; aggiunta tabella *"Difese in serie"* a 10 layer (network ingress → audit log) con colonne "blocca / non blocca" — il layer 3 RateLimiter dichiara esplicitamente "brute-force di token invalidi non blocca, per design"; aggiunta sotto-sezione *"Versioning dello schema"* nell'audit (no `schema_version` oggi, breaking changes vietati senza migration plan); sezione `Mitigazioni a livello deploy` riscritta con dettagli step 11 (gruppo `systemd-journal`, drop-in `ReadWritePaths`, ACL probe attivo, hardening unit completo); permessi journal default → `systemd-journal` (NON `adm`); sezione *"two-key EvoTrader/Robo-PAC"* trasformata in riferimento prospettico a `PM-MCP-PROJECT.md → Cosa il bridge NON farà mai`; eventi auditati: dichiarato esplicitamente l'override `outcome ∈ {denied, error}` su tool read.
  - `docs/SETUP.md` riscritto da capo: pre-requisiti, layout file/permessi, clone + venv, config, dettaglio `install.sh` (8 fasi + output atteso), smoke test locale, avvio systemctl, ingress cloudflared, Cloudflare Access raccomandato, registrazione connector, verifica end-to-end, recupero token (rotazione via `rm token.sha256` + rilancio installer), upgrade, disinstallazione completa.
  - `README.md` aggiornato: status `step 8 completato` → `MVP completato (step 1-12)`, suite 364 verdi; aggiunta lista 21 tool per area; tabella step implementati 1-12 tutti `✅`; rimossa sezione "Pending" stale.
  - Suite invariata: `364 passed`. Documentazione non tocca codice Python.

- `ec7b1e7` — step 13: post-deploy hardening basato sull'audit
  del connector (vedi *Stato deploy → Findings post-deploy*).
  - `deploy/install.sh`: nuovo step 7b "ACL traversal sui parent path".
    Applica `setfacl -m u:devbox-bridge:--x` su `dirname(PROJECTS_ROOT)`
    e su `PROJECTS_ROOT` stesso. `--x` = execute-only (traversal,
    non listing/read) → least-privilege rispetto a `chmod o+x` che
    darebbe accesso al world. Idempotente. Fix-bloccante per il caso
    `/home/hypn0` default `0750 hypn0:hypn0` su Ubuntu Server.
  - `src/devbox_bridge/security/paths.py`: `resolve_within_any` riscritto
    con ordine **whitelist → esistenza** invece di esistenza → whitelist.
    (a) `cand.resolve(strict=False)` normalizza `..` e segue symlink
    intermedi esistenti; check whitelist su questo. (b) Solo se
    whitelist passa, `cand.resolve(strict=True)` per esistenza →
    propaga `FileNotFoundError`. (c) Defense-in-depth: re-validate
    post-strict-resolve contro symlink finali che escono. Estratto
    helper privato `_is_under_any()`. Razionale: prima di questa
    modifica, un path fuori whitelist + inesistente sollevava
    `FileNotFoundError` (sintomo: client vedeva "non esiste") invece
    di `PathSecurityError` (sintomo: "non in whitelist"). Asimmetria
    di error message → info-leak debole sull'esistenza di file fuori
    whitelist.
  - `tests/test_path_safety.py`: 2 nuovi test (`test_resolve_within_any_outside_whitelist_nonexistent_path_rejected`,
    `test_resolve_within_any_inside_whitelist_nonexistent_propagates`)
    che fissano il contratto del nuovo ordine.
  - `docs/SECURITY.md`: aggiunte sotto-sezioni *"Perché l'ordine
    whitelist → esistenza"*, *"list_systemd_services — asimmetria
    intenzionale rispetto a read_journalctl"* (metadati pubblici vs
    log content, single-tenant), *"PathSecurityError vs PermissionError —
    distinguere il livello d'errore"* (sintomi diversi, proprietà di
    sicurezza equivalente).
  - `docs/TOOLS.md`: `tail_log` validation aggiornata con il nuovo
    ordine; `list_systemd_services` con nota esplicita "niente
    whitelist hard, asimmetria intenzionale".
  - `docs/SETUP.md`: aggiunto step 5 al flow `install.sh` per l'ACL
    traversal sui parent path.
  - Suite: `366 passed` (+2 dei nuovi). Smoke E2E sul deploy
    (servizio in produzione su devbox) verificato:
    - `read_file("devbox-bridge", "README.md")` → 2761 bytes, sha8
      `e246936b` ✅ (era EACCES prima del fix A).
    - `read_file(..., "../../etc/passwd")` → `PathSecurityError`
      esplicito ✅ (prima era EACCES).
    - `tail_log("/opt/devbox-bridge/logs/nonexistent.log")` →
      "non è dentro alcuna whitelist root" ✅ (prima era "non esiste").
    - `tail_log("/var/log/devbox-bridge/nonexistent.log")` →
      "non esiste" ✅ (caso legittimo dentro whitelist).

- *follow-up step 13* — `install.sh` aggiornato per gestire git
  `safe.directory`. I tool git fallivano con `fatal: detected dubious
  ownership in repository at '/home/hypn0/projects/...'` perché git
  2.36+ rifiuta repo owned da utente diverso da quello corrente.
  Single-tenant: il repo è di `hypn0`, il servizio gira come
  `devbox-bridge`. Fix: `install.sh` ora aggiunge ogni `canon` di
  progetto a `safe.directory` nel gitconfig globale del service user
  (`/opt/devbox-bridge/.gitconfig`), idempotente (skip se già
  presente). Il file viene letto ma mai scritto a runtime
  (compatibile con `ProtectSystem=strict`). Smoke test post-fix:
  `git_status` su `devbox-bridge` ritorna `branch=main, clean=False`
  come atteso (working tree dirty per `install.sh` modificato in
  questo follow-up).

## Step pending (in ordine)

MVP development chiuso: tutti gli step 1-12 committati e pushati,
servizio deployato e operativo localmente. Resta solo il wiring rete
+ registrazione connector descritti in *Stato deploy → Pending lato
operatore*. Niente codice da scrivere.

Per quando si tornerà sul progetto (V1 post-MVP, vedi
`PM-MCP-PROJECT.md → Definition of Done — V1`):

- Cloudflare Access OAuth davanti al tunnel
- Audit log shipping (rsync notturno verso storage esterno)
- Backup automatico di `/etc/devbox-bridge/token.sha256`
- Healthcheck endpoint pubblico read-only per uptime monitoring
- Almeno 5 dei 14 progetti reali configurati e testati end-to-end

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
- **Tutti i tool exec gated da `write_enabled`** (anche `run_tests`/`run_lint`/`run_build`). Motivo: pytest scrive `.pytest_cache`/`__pycache__`, ruff/black `--fix` riscrive sorgenti, build genera artefatti, `npm install` tocca `node_modules`. "read-only project" significa "il filesystem del progetto non viene toccato": permettere esecuzione viola quel contratto, anche per "modifiche innocue". Fail-secure.
- **Whitelist regex bypassata per `run_tests`/`run_lint`/`run_build`** (deny list applicata sempre). Motivo: i 3 comandi configurati sono amministrativamente autorizzati (li scrive l'utente in `config.yaml`, SoT del progetto). Costringerli anche in `command_whitelist` è ridondante UX-wise. La deny list resta per fail-secure su errori di config tipo `test_command: "pytest && rm -rf /etc"`. `check_deny_list()` esposta come funzione pubblica esplicita in `security/commands.py` (non side-effect di whitelist vuota).
- **`exit_code != 0` e `timed_out` NON sollevano eccezione nei tool exec.** Differenza intenzionale dai tool git. Motivo: per `run_tests` un exit non-zero è normale ~30% delle volte (test rossi); sollevare sarebbe anti-pattern, il client ha bisogno di stdout/stderr per capire perché. Audit registra `outcome="success"` (il bridge ha eseguito il subprocess) con `outcome_detail` granulare.
- **Campo `outcome_detail` audit (`completed`/`nonzero_exit`/`timed_out`).** Motivo: serve granularità in fase di debrief log senza promuovere a `outcome="error"`. `outcome` resta nel dominio fisso `{success, denied, error}` per non rompere lo schema; `outcome_detail` è top-level opzionale, popolato solo per i tool exec.
- **`shutil.which` non risolve path relativi al cwd del subprocess.** Motivo: shutil.which usa il cwd del processo bridge, non il `cwd=` passato a `subprocess.run`. Quindi `test_command: "./venv/bin/pytest"` solleva `ExecutableNotFoundError`. Comportamento intenzionale e documentato: configurare nomi binari nel PATH o path assoluti.
- **Comando troncato a 500 char in `args_summary` audit** (`COMMAND_AUDIT_TRUNCATE_CHARS`). Motivo: anti log-poisoning. `run_command(command="echo " + "A"*100000)` non deve generare 100KB di "A" in ogni linea audit. La truncation preserva i primi 500 char (sempre sufficienti a vedere l'argv0 e i flag iniziali).
- **Whitelist `system:` con semantica fail-secure su lista esplicitamente vuota.** `system:` omesso (o `system: {}`) → default permissivi onboarding-friendly. `system: { log_paths_whitelist: [] }` (o equivalenti) → letteralmente nessuna risorsa accessibile. Motivo: riempire automaticamente una lista YAML svuotata sarebbe fail-open — un operatore che ha esplicitamente svuotato vuole quello, non un default. Default come letterali in `config.py` solo (single source of truth).
- **`outcome="denied"` e `"error"` sempre auditati** (ignorano `audit_reads` e la classificazione read/write dell'evento). Motivo: un denial/errore è materiale forense, non rumore — `audit_reads=false` di default punta a sopprimere il volume delle read OK, non a nascondere i fail. Modifica in `AuditLogger.log` (step 10) per supportare denial sui read tool sistema senza dover esplodere il numero di event class.
- **`MAX_LOG_OUTPUT_BYTES = 512 KB` per `tail_log`/`read_journalctl`.** Motivo: 512 KB ≈ metà context window 200K-token. Per i casi d'uso reali del bridge (debugging on-the-fly, "ultime 200 righe del log") è già abbondante. Limite più alto (es. 1 MB) saturerebbe metà context Claude per una sola tool call. Se serve più, iterare con `lines` minore.
- **`resolve_within_any` ordine non significativo, primo match vince è dettaglio implementativo.** Motivo: il path è valido se cade in almeno un root della whitelist. Sovrapposizioni di root (`/var/log` e `/var/log/devbox-bridge`) restano consistenti senza che l'utente debba pensare all'ordine. Root inesistenti saltati silenziosamente — smontare un mountpoint non deve rompere l'intera validazione.
- **Permessi journal: `systemd-journal` per il service user, NON `adm`.** Motivo: con la `systemd_unit_whitelist` di default (`["devbox-bridge.service"]`) `read_journalctl` legge solo il proprio servizio; `systemd-journal` è sufficiente e segue least privilege. `adm` aggiungerebbe accesso a `/var/log/syslog`, `/var/log/auth.log`, ecc. che il bridge per design non tocca. Se in futuro l'operatore amplia `tail_log` aggiungendo `/var/log/syslog` a `log_paths_whitelist`, dovrà aggiungere `adm` a mano (decisione consapevole, non automatica). `deploy/install.sh` fa `usermod -aG systemd-journal devbox-bridge` e fail-fast se la membership non è applicata.

- **Drop-in `/etc/systemd/system/devbox-bridge.service.d/projects.conf` con `ReadWritePaths=` derivato da `config.yaml`.** Motivo: defense in depth in *serie*, non ridondante. Il check applicativo `write_enabled` nei tool è una difesa; il `ReadWritePaths` di systemd è un bind mount kernel-level: anche se un baco bypassasse il check applicativo, il filesystem nel namespace del servizio sarebbe ancora read-only sui progetti non opt-in. La unit base resta statica, parametrizzata via drop-in (pattern systemd nativo, non "unit generata da template"). Drop-in **sempre riscritto da zero** dall'installer — anche vuoto se zero progetti `write_enabled` — per garantire che downgrade `rw→ro` non lasci entry stale. Validazione path nel drop-in: `realpath -e` (fail se non esiste), reject di symlink, reject di path fuori da `/home/hypn0/projects/`. `setfacl` da solo non basterebbe perché systemd lo bypassa via namespace; le due difese sono complementari.

- **Filesystem ACL probe via `setfacl`+`getfacl` su `mktemp`, NON grep su mount options.** Motivo: su ext4 moderno (Ubuntu 24.04) `acl` è on-by-default e *non compare* in `mount` output. Un check tipo `mount | grep acl` falserebbe negativo su sistemi perfettamente funzionanti. Il probe attivo (crea file temporaneo, applica ACL, verifica via getfacl, rimuove) funziona indipendentemente da come le ACL sono abilitate (mount option, feature flag del fs, ecc.).

- **Sequenza esecuzione `install.sh`: ACL → drop-in → `daemon-reload`.** Motivo: invertire ACL e drop-in apre una finestra in cui systemd (a `daemon-reload` + `restart`) ha aggiornato i bind mount ma le ACL non sono ancora state applicate → il servizio scrive e prende `EACCES`, log strani solo in upgrade ma non in install pulito. Costo zero rispettare l'ordine, evita un bug sottile.

- **`/opt/devbox-bridge` ownership `devbox-bridge:devbox-bridge 0750`** (creata vuota dall'installer). Motivo: l'operatore fa `sudo -u devbox-bridge git clone <url> /opt/devbox-bridge` direttamente (git clone su dir esistente vuota funziona), senza serve `sudo` per `git pull` futuri. Il codice è di proprietà del service user, coerente con "il bridge gestisce il suo ambiente di runtime". Nessuna ridondanza con `chown root:devbox-bridge`: 0750 con owner non-write per devbox-bridge bloccherebbe il clone.

- **`config.yaml` mai sovrascritto, token mai rigenerato dall'installer se esistono.** Motivo: idempotenza fail-secure. Un rilancio accidentale di `install.sh` su sistema in produzione non deve invalidare il token attivo (rotazione richiede `rm token.sha256` esplicito) né resettare la config con i progetti abilitati. ACL e drop-in invece vengono riapplicati ogni volta — sono derivabili da `config.yaml`, "stato canonico riprodotto dal SoT", non hanno equivalente di "config preferenziale dell'operatore".

- **Opzioni scartate per access control progetti** (vedi `FAILURES.md` 2026-05-04): aggiungere `devbox-bridge` al gruppo `hypn0` viola least privilege (espone `~/.ssh`, `~/.config`, progetti non opt-in); far girare il servizio come `hypn0` annulla `ProtectHome=read-only` e perde la garanzia kernel-level. ACL chirurgiche + drop-in `ReadWritePaths` è la sola opzione coerente con il threat model.

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

Atteso allo stato attuale (post step 11): `364 passed` (invariato rispetto allo step 10 — step 11 è solo file di deploy, niente codice Python toccato).

Pre-flight per i file di deploy:

```bash
bash -n deploy/install.sh                     # syntax check
python3 -c "import yaml; yaml.safe_load(open('deploy/docker-compose.yml'))"
python3 -c "import yaml; yaml.safe_load(open('deploy/cloudflared-config.yml'))"
```

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
