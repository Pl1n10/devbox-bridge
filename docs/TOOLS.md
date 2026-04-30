# TOOLS — Reference dei tool MCP esposti

> Stato step 9: i tool filesystem, git ed esecuzione sono registrati nel
> server FastMCP e disponibili su HTTP `/mcp`. Sistema è ancora placeholder.

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

Placeholder step 10:

- `get_system_info()` — read
- `list_systemd_services(filter='devbox-')` — read
- `tail_log(path, lines=100)` — read
