# TOOLS — Reference dei tool MCP esposti

> Stato step 10: i tool filesystem, git, esecuzione e sistema sono tutti
> registrati nel server FastMCP e disponibili su HTTP `/mcp`.

## Transport

- Endpoint locale: `http://127.0.0.1:8765/mcp`
- Auth richiesta: `Authorization: Bearer <token>`
- Token invalido/mancante: `401 unauthorized`
- Rate limit superato: `429 too many requests`, header `Retry-After: 60`

## Filesystem

Implementati e registrati:

- `list_projects()` — read. Ritorna nome progetto, path, flag write/push e
  presenza dei comandi test/lint/build. Non espone whitelist o env passthrough.
- `read_file(project, rel_path)` — read. Legge testo UTF-8 dentro la project
  root, rifiuta binari, traversal e file oltre `max_read_bytes`.
- `list_directory(project, rel_path=".")` — read. Lista entry immediate e marca
  directory skipped (`node_modules`, `.git`, build cache, ecc.).
- `search_files(project, pattern, glob="*", max_matches=500)` — read. Wrapper
  ripgrep JSON con glob anti-traversal e path relativi.
- `write_file(project, rel_path, content, create=False)` — **write**. Richiede
  `write_enabled=true`; crea file nuovo solo con `create=true`.
- `apply_patch(project, rel_path, old, new)` — **write**. Sostituisce tutte le
  occorrenze di `old`; rifiuta binari e no-op `old == new`.

Audit:

- Read auditati solo se `audit.audit_reads=true`.
- Write sempre auditati.
- `content` di `write_file` non viene loggato in chiaro: viene riassunto con
  bytes e hash breve.

## Git

Implementati e registrati. Tutti eseguono `git --no-pager <cmd>` con
`subprocess.run` (mai `shell=True`), `cwd=project_root`, env sanitizzato
via `security/env.py`, timeout 30s.

Read:

- `git_status(project)` — porcelain v1 con `-z`. Ritorna `branch`, `detached`,
  `upstream`, `ahead`, `behind`, `staged[]`, `unstaged[]`, `untracked[]`,
  `clean`. Rename/copy: la entry segnala `code=R|C` e include `orig`.
- `git_diff(project, staged=False, path=None)` — testo unified diff. Se
  `path` è valorizzato, viene validato con `resolve_within` prima di passare
  a `git diff -- <rel>`. Output troncato a 2 MB con `truncated: true`.
- `git_log(project, limit=20)` — campi `hash`, `short_hash`, `author_name`,
  `author_email`, `date` (ISO 8601), `subject`. `limit` clampato a 200 (max).
- `git_branch_current(project)` — `{branch, detached, head}`. In stato
  detached `branch` è `None` e `head` contiene lo SHA40.

Write (richiedono `write_enabled: true`):

- `git_create_branch(project, name)` — `git checkout -b`. Nome validato con
  `git check-ref-format --branch`; refiuta newline, `\0` e branch già
  esistenti (`GitCommandError` con stderr esplicito).
- `git_commit(project, message, paths)` — paths obbligatori (mai
  `git commit -a`). Ogni path validato con `resolve_within`. Se `paths`
  non hanno modifiche, fallisce esplicitamente.
- `git_push(project, remote='origin')` — push del branch corrente
  (`git push <remote> HEAD:<branch>`). Richiede `allow_push: true` (altrimenti
  `PushNotAllowedError`). Remote validato con regex stretta. Backstop
  hardcoded contro `--force`/`--mirror`/`--delete`/`--all`/`--prune`/
  `--force-with-lease`. Output stdout/stderr troncato a 64 KB.

NON implementati di proposito: `reset --hard`, `push --force`, `clean`,
`branch -D`. Vedi `devbox-bridge-brief.md:55`.

Mapping audit / outcome:

- `WriteNotAllowedError` (write su progetto read-only) →
  `event="path.rejected"`, `outcome="denied"`.
- `PushNotAllowedError` (push su progetto con `allow_push=false`) →
  `event="tool.git_push"`, `outcome="denied"`.
- `PathSecurityError` (path traversal in `git_diff`/`git_commit`) →
  `event="path.rejected"`, `outcome="denied"`.
- `GitCommandError`, `BranchNameError`, `RemoteNameError`, ... →
  `event="tool.<name>"`, `outcome="error"`.

## Esecuzione

Implementati e registrati. Tutti eseguono via `subprocess.run` con lista args
(mai `shell=True`), `cwd=project_root`, env sanitizzato via `security/env.py`,
`stdin=DEVNULL`. Tutti e 4 richiedono `write_enabled: true` sul progetto:
**read-only mode = no execution**, anche per i comandi configurati in
`config.yaml` (test/lint/build scrivono cache, artefatti, fix lint;
fail-secure).

Tool:

- `run_tests(project)` — esegue `project.test_command`. Timeout default 300s.
- `run_lint(project)` — esegue `project.lint_command`. Timeout default 300s.
- `run_build(project)` — esegue `project.build_command`. Timeout default 300s.
- `run_command(project, command, timeout=60)` — comando arbitrario. Timeout
  user-provided in `[1, 600]`s.

Validazione comando:

- `run_command` → deny list **+** whitelist regex (`re.fullmatch` su almeno un
  pattern in `project.command_whitelist`).
- `run_tests` / `run_lint` / `run_build` → solo deny list. La whitelist è
  bypassata: i 3 comandi sono autorizzati amministrativamente perché stanno
  in `config.yaml` (SoT del progetto). La deny list resta come fail-secure
  contro errori tipo `test_command: "pytest && rm -rf /etc"` in config.

Schema response (uguale per i 4 tool):

```json
{
  "command": "pytest -q",
  "exit_code": 0,
  "duration_ms": 1234.5,
  "stdout": "...",
  "stderr": "...",
  "stdout_truncated": false,
  "stderr_truncated": false,
  "timed_out": false
}
```

`stdout` e `stderr` sono troncati a 100 KB con flag `*_truncated`. `exit_code`
è il codice di uscita reale del subprocess. `timed_out=true` (con
`exit_code=-1`) se il subprocess ha sforato il timeout.

**`exit_code != 0` e `timed_out` NON sollevano eccezione**: sono outcome
legittimi (test che falliscono, build lenta). Il client riceve la response
normale e decide cosa farne. Differenza intenzionale dai tool git, dove un
exit-code anomalo è un errore vero.

Eccezioni sollevate (event/outcome nel server audit tra parentesi):

- `WriteNotAllowedError` — progetto con `write_enabled=false`
  → `path.rejected` / `denied`.
- `CommandRejectedError` — comando bloccato dalla deny list o non in
  whitelist → `command.rejected` / `denied`.
- `NoCommandConfiguredError` — `run_tests`/`lint`/`build` su progetto senza
  il rispettivo `*_command` → `tool.<name>` / `error`.
- `ExecutableNotFoundError` — `argv[0]` non in PATH (anche path relativi
  tipo `./venv/bin/pytest`: `shutil.which` non risolve rispetto al cwd del
  subprocess, configurare nomi binari nel PATH o path assoluti) →
  `tool.<name>` / `error`.
- `TimeoutOutOfRangeError` — `run_command(timeout=...)` fuori da `[1, 600]`
  → `tool.run_command` / `error`.

Audit `outcome_detail` per i tool exec (popolato solo su `outcome="success"`):

- `completed` — subprocess terminato con `exit_code=0`.
- `nonzero_exit` — subprocess terminato con `exit_code != 0`.
- `timed_out` — subprocess interrotto per timeout.

Non promosso a `outcome="error"`: il bridge ha eseguito il subprocess
correttamente, il dettaglio descrive cosa è successo nel processo figlio.

Audit `args_summary` per i tool exec:

- `command` troncato a 500 char + `...[truncated]` se più lungo (protezione
  log poisoning).
- `stdout` e `stderr` riassunti via `summarize_command_output()` (head 500ch
  + tail 500ch + `total_sha8` + `total_bytes` + `truncated`), non in chiaro.
- `exit_code`, `duration_ms`, `timed_out`, `stdout_truncated`,
  `stderr_truncated` propagati come field di sintesi.

## Sistema

Implementati e registrati. Tutti read-only. Niente `write_enabled` requirement
(non scrivono filesystem). Eseguiti via `subprocess.run` con lista args (mai
`shell=True`), `cwd=None` (system-wide), env sanitizzato via `security/env.py`,
`stdin=DEVNULL`, timeout 30s.

**Read-only mode:** indipendente dal `write_enabled` dei progetti — questi
tool guardano lo stato della macchina, non i progetti, quindi sono sempre
accessibili (read).

Tool:

- `get_system_info()` — hostname, kernel, arch, uptime, load, memoria, disco.
  Niente parametri. Resiliente a fallimenti parziali: se `df` o `uname` non
  disponibili, il campo corrispondente resta a default (None / lista vuota)
  ma il tool non solleva.
- `list_systemd_services(name_filter=None)` — wrapper di
  `systemctl list-units --type=service --all --no-pager --plain --no-legend`,
  filtrato per substring sul nome unit. `name_filter=None` → usa
  `system.systemd_filter_default` di config (default `devbox-`); stringa
  vuota → nessun filtro (tutte le unit).
- `tail_log(path, lines=100)` — `tail -n N <path>`. `path` deve essere
  assoluto, esistere ed essere dentro UNO dei root in
  `system.log_paths_whitelist`.
- `read_journalctl(unit, lines=100)` — `journalctl -u <unit> -n N --no-pager`.
  `unit` deve matchare regex stretta E essere in
  `system.systemd_unit_whitelist`. Su Ubuntu, l'utente del bridge deve essere
  in gruppo `adm` o `systemd-journal` per leggere unit system-wide.

Schema response `tail_log` / `read_journalctl`:

```json
{
  "source": "/var/log/devbox-bridge/audit.log",
  "lines_requested": 100,
  "exit_code": 0,
  "content": "...",
  "content_truncated": false
}
```

Output troncato a 512 KB (metà di un context window 200K-token). Se il log
è più grosso, iterare con `lines` minore.

Schema response `list_systemd_services`:

```json
{
  "filter": "devbox-",
  "exit_code": 0,
  "services": [
    {"unit": "devbox-bridge.service", "load": "loaded", "active": "active",
     "sub": "running", "description": "..."}
  ]
}
```

Schema response `get_system_info`:

```json
{
  "hostname": "devbox",
  "kernel": "6.8.0-110-generic",
  "arch": "x86_64",
  "uptime_seconds": 213978,
  "load": {"1": 0.5, "5": 0.4, "15": 0.3},
  "memory_bytes": {"total": 16655495168, "available": ..., "free": ...},
  "disk": [
    {"source": "/dev/...", "size": "98G", "used": "14G", "avail": "80G",
     "use_pct": "15%", "mount": "/"}
  ]
}
```

Note schema:

- `uptime_seconds` è `int` (no rumore decimale nei log audit).
- `memory_bytes` ritorna byte (kB di `/proc/meminfo` × 1024 una volta sola
  alla lettura). Più chiaro al consumer di `memory_kb` ambiguo.
- I campi `disk[]` sono **intenzionalmente human-readable** (output `df -h`):
  `size`/`used`/`avail` sono stringhe tipo `"98G"`, `use_pct` come `"15%"`.
  **Non parsare numericamente.** Se serviranno byte raw, in futuro si
  aggiungerà un `disk_bytes` separato.

Eccezioni sollevate (event/outcome nel server audit tra parentesi):

- `LogPathNotAllowedError` — path assoluto fuori da
  `system.log_paths_whitelist` (incluso symlink dentro la whitelist che
  punta fuori). → `path.rejected` / `denied`.
- `LogPathNotFoundError` — path whitelistato ma file non esiste. →
  `tool.tail_log` / `error`.
- `JournalctlUnitNotAllowedError` — unit non in whitelist o nome non valido.
  → `tool.read_journalctl` / `denied`.
- `FilterPatternError` — `name_filter` di `list_systemd_services` con
  caratteri non ammessi (defense-in-depth contro injection). →
  `tool.list_systemd_services` / `error`.
- `LinesOutOfRangeError` — `lines` fuori da `[1, 5000]`. → `error`.
- `TailNotAvailableError` / `SystemctlNotAvailableError` /
  `JournalctlNotAvailableError` — binario assente nel PATH. → `error`.

**Audit policy:** read tool con `outcome="success"` non auditati di default
(`audit_reads=false`). Read tool con `outcome="denied"` o `"error"` sono
**sempre auditati** — un denial è materiale forense, non rumore.

Whitelist log/unit configurate in `config.yaml` sotto `system:` (vedi
`SECURITY.md` per la semantica fail-secure delle whitelist esplicitamente
vuote vs sezione omessa).
