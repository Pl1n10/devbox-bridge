# TOOLS — Reference dei tool MCP

Reference completo dei 21 tool registrati dal server FastMCP. Per il threat
model e l'audit log vedi [`SECURITY.md`](SECURITY.md); per il deploy vedi
[`SETUP.md`](SETUP.md).

I nomi dei tool e le signature in questo documento corrispondono uno-a-uno a
quanto registrato in `src/devbox_bridge/server.py::create_mcp`. Le signature
visibili al client MCP includono i parametri esposti da FastMCP; alcune
funzioni interne accettano keyword-only extra non raggiungibili via MCP.

## Transport

- Endpoint locale: `http://127.0.0.1:8765/mcp` (path `/mcp`,
  costante `MCP_HTTP_PATH` in `server.py`).
- Auth: header `Authorization: Bearer <token>`.
- 401 `unauthorized` per token mancante/invalido (body generico, vedi
  `SECURITY.md`).
- 429 `too many requests` con header `Retry-After: 60` per rate limit.
- I tool ritornano JSON. I path nei response sono **relativi alla project
  root**, mai assoluti — vedi `tools/filesystem.py::_rel_to_root`.

## Convenzioni comuni

- `project: str` deve essere un nome dichiarato in `config.yaml` sotto
  `projects:`. Sconosciuto → `KeyError` da `cfg.project()`.
- Path validation: ogni `rel_path` passa da
  `security.paths.resolve_within(project_root, rel_path)` →
  `PathSecurityError` su traversal, simboli `..`, simlink che escono dalla
  root, path assoluti che cadono fuori. Test:
  `tests/test_path_safety.py::test_dotdot_traversal_rejected`,
  `::test_symlink_escaping_rejected`,
  `::test_absolute_outside_rejected`,
  `::test_null_byte_in_path_rejected`.
- `tail_log` usa la variante multi-root
  `security.paths.resolve_within_any(path, allowed_roots)` (test
  `tests/test_path_safety.py::test_resolve_within_any_*`).
- Subprocess: `subprocess.run` con lista args (mai `shell=True`),
  `stdin=subprocess.DEVNULL`, env sanitizzato via `security/env.sanitize_env`.
  Test trasversale: `tests/test_tools_execution.py::test_run_command_does_not_use_shell`.
- Audit: ogni invocazione passa da `server._call_with_audit` che decide
  evento, outcome, sintesi argomenti — vedi `SECURITY.md → Audit logging`.

## Filesystem (6 tool)

Implementazione: `src/devbox_bridge/tools/filesystem.py`.
Tutti i tool ritornano `path` relativo alla project root. `read_file` e
`apply_patch` rifiutano file binari (heuristic: `\x00` nei primi 8 KB).
Encoding UTF-8 strict.

### `list_projects()`

Enumera i progetti dichiarati in `config.yaml`, esponendo solo i campi
sicuri. Niente `command_whitelist` né `env_passthrough` (dettagli interni).

- Parametri: nessuno.
- Return: `list[{name, path, write_enabled, allow_push, has_test_command,
  has_lint_command, has_build_command}]`.
- Errori: nessuno previsto in normale operatività.
- Audit: `event="tool.list_projects"`, `outcome="success"`. Read →
  auditato solo se `audit.audit_reads=true`.
- Test: `tests/test_tools_filesystem.py::test_list_projects_returns_minimal_shape`,
  `::test_list_projects_does_not_leak_internal_fields`.

### `read_file(project, rel_path)`

Legge un file di testo dentro la project root.

- Parametri:
  - `project: str`
  - `rel_path: str` — relativo o assoluto purché dentro la project root.
- Return: `{path, bytes, encoding="utf-8", content_sha8, content}`.
- Errori sollevabili (mappati sull'audit del server):
  - `PathSecurityError` → `path.rejected` / `denied`.
  - `FileNotFoundError`, `IsADirectoryError` → `tool.read_file` / `error`.
  - `FileTooLargeError` (file > `max_read_bytes`, default 10 MB, ceiling
    50 MB) → `error`. Test:
    `tests/test_tools_filesystem.py::test_read_file_above_max_read_bytes_refused`.
  - `BinaryFileError` → `error`. Test: `::test_read_file_binary_refused`.
  - `UnicodeDecodeError` (UTF-8 strict, niente sostituzione silenziosa) →
    `error`. Test: `::test_read_file_invalid_utf8_refused`.
- Audit: read → soggetto a `audit.audit_reads`.

### `write_file(project, rel_path, content, create=False)`

Scrive `content` in `rel_path`. Overwrite totale se il file esiste.

- Parametri:
  - `project: str`, `rel_path: str`, `content: str`,
    `create: bool = False`.
- Semantica `create`:
  - file esiste → flag ignorato, overwrite;
  - file non esiste e `create=False` → `FileNotFoundError`;
  - file non esiste e `create=True` → crea anche le directory intermedie.
- Return: `{path, bytes, content_sha8, created}`.
- Errori:
  - `WriteNotAllowedError` (progetto con `write_enabled=false`) →
    `path.rejected` / `denied`. Test:
    `tests/test_tools_filesystem.py::test_write_file_denied_when_write_disabled`.
  - `PathSecurityError` → `path.rejected` / `denied`.
  - `IsADirectoryError`, `FileNotFoundError` → `error`.
- Audit: write → sempre auditato. `content` non viene loggato in chiaro:
  `args_summary` contiene solo `bytes` + `content_sha8`
  (`audit.summarize_content`).

### `apply_patch(project, rel_path, old, new)`

`str.replace(old, new)` su tutte le occorrenze di `old` nel contenuto del
file, in una singola pass. **Non è atomico a livello filesystem**: la
scrittura usa `Path.write_bytes`, non un rename + replace. Un crash in
mezzo può lasciare il file troncato — il client deve trattare `apply_patch`
come "best effort, verificabile via `content_sha8_after`".

- Parametri: `project`, `rel_path`, `old: str`, `new: str`.
- Return: `{path, occurrences_replaced, bytes_before, bytes_after,
  content_sha8_before, content_sha8_after}`.
- Errori:
  - `WriteNotAllowedError` → `path.rejected` / `denied`.
  - `PathSecurityError`, `BinaryFileError` → `denied` / `error`.
  - `ValueError` se `old == new` (no-op rifiutato) o `old` non trovato.
    Test:
    `tests/test_tools_filesystem.py::test_apply_patch_old_equals_new_refused`,
    `::test_apply_patch_old_not_found`.
- Audit: write → sempre auditato.

### `list_directory(project, rel_path=".")`

Elenco entry immediate di una directory dentro il progetto.

- Return: `{path, entries: [{name, type, ...}]}`.
  - `type ∈ {file, dir, symlink, other}`.
  - `dir` ha `skipped: bool` (true se in `SKIP_DIRS`: `.git`,
    `node_modules`, `__pycache__`, `.venv`, `dist`, `build`, ecc. —
    costante `SKIP_DIRS` in `tools/filesystem.py`).
  - `file` ha `size`.
  - `symlink` ha `target` come path relativo a root, oppure `<external>`
    se esce dal progetto (NON viene seguito).
- Errori: `PathSecurityError`, `FileNotFoundError`, `NotADirectoryError`.
- Audit: read.
- Test:
  `tests/test_tools_filesystem.py::test_list_directory_marks_skipped_dirs`,
  `::test_list_directory_external_symlink_marked`.

### `search_files(project, pattern, glob="*", max_matches=500)`

Wrapper su `ripgrep --json`. Skip dirs aggiuntive su `SKIP_DIRS`. Skip
binari per default ripgrep.

- Parametri:
  - `pattern: str` — regex passata a ripgrep.
  - `glob: str = "*"` — pattern fnmatch (`*.py`, `src/**`,
    alternazione `{a,b}`, negazione `!`). Validato: niente `..`, niente
    path assoluto, niente `~`. Test:
    `tests/test_tools_filesystem.py::test_search_files_glob_traversal_refused`,
    `::test_search_files_glob_absolute_refused`,
    `::test_search_files_glob_home_relative_refused`.
  - `max_matches: int = 500` — clamp in tronco lato Python; deve
    essere ≥ 1.
- Return: `{matches: [{path, line, column, text}], truncated, ...}`
  (path relativi alla project root).
- Errori:
  - `GlobSecurityError` → `path.rejected` / `denied`.
  - `RipgrepNotFoundError` → `error`.
  - `ValueError` su `max_matches < 1`.
- Audit: read.

## Git (7 tool)

Implementazione: `src/devbox_bridge/tools/git.py`. Tutti via
`git --no-pager <cmd>` con `subprocess.run`, `cwd=project_root`,
`timeout=GIT_TIMEOUT_SECONDS=30s`. Env sanitizzato + `GIT_TERMINAL_PROMPT=0`
+ `GIT_OPTIONAL_LOCKS=0` (no prompt interattivi, no lock opportunistici).

### `git_status(project)` (read)

`git status --porcelain=v1 --branch -z`.

- Return: `{branch, detached, upstream, ahead, behind, staged, unstaged,
  untracked, clean}`.
  - Rename/copy: l'entry segnala `code=R|C` e include `orig`.
  - Repo nuovo (no commit): `branch` valorizzato, ahead/behind=0.
  - Detached HEAD: `branch=null`, `detached=true`.
- Errori: `NotARepositoryError` → `error`. `GitCommandError` → `error`.
- Test:
  `tests/test_tools_git.py::test_git_status_clean`,
  `::test_git_status_with_staged_and_unstaged`,
  `::test_git_status_not_a_repository`.

### `git_diff(project, staged=False, path=None)` (read)

Unified diff testuale.

- Parametri:
  - `staged: bool = False` → `git diff --cached`.
  - `path: str | None = None` → se valorizzato passa da `resolve_within`
    e viene appeso come `-- <rel>`.
- Return: `{staged, path, diff, bytes, truncated}`. Output troncato a
  `MAX_DIFF_BYTES=2 MB`.
- Errori: `PathSecurityError` (path traversal nel filtro) → `denied`.
  `NotARepositoryError` / `GitCommandError` → `error`.
- Test:
  `tests/test_tools_git.py::test_git_diff_path_filter`,
  `::test_git_diff_path_traversal_refused`.

### `git_log(project, limit=20)` (read)

Ultimi N commit con record separator non-stampabile (no collisione con
commit message).

- Parametri:
  - `limit: int = 20` — semantica:
    - `limit < 1` → `ValueError("limit deve essere >= 1")` (rifiuto
      esplicito, niente fallback silenzioso a 1).
    - `limit > MAX_LOG_LIMIT` (200) → clamp silenzioso via
      `min(limit, MAX_LOG_LIMIT)`. Il `limit` nel response riflette il
      valore effettivo applicato, non quello richiesto.
- Return: `{limit, commits: [{hash, short_hash, author_name,
  author_email, date, subject}]}`. `date` è ISO-8601 (`%aI`).
- Errori: `ValueError` su `limit < 1`. Repo senza commit → `commits: []`.
- Test:
  `tests/test_tools_git.py::test_git_log_default`,
  `::test_git_log_limit_clamp_to_max`,
  `::test_git_log_repo_without_commits`.

### `git_branch_current(project)` (read)

- Return:
  - branch attivo: `{branch, detached: false, head: null}`.
  - detached: `{branch: null, detached: true, head: <SHA40>}`.
- Test:
  `tests/test_tools_git.py::test_git_branch_current`,
  `::test_git_branch_current_detached`.

### `git_create_branch(project, name)` (write)

`git checkout -b <name>`.

- Parametri:
  - `name: str` — validato con `git check-ref-format --branch`. Refiuta
    newline, `\0`, branch già esistenti.
- Return: `{branch, from: <SHA40>}`.
- Errori:
  - `WriteNotAllowedError` → `path.rejected` / `denied`. Test:
    `tests/test_tools_git.py::test_git_create_branch_requires_write_enabled`.
  - `BranchNameError` (nome invalido) → `error`. Test:
    `::test_git_create_branch_invalid_name`,
    `::test_git_create_branch_with_newline_refused`.
  - `GitCommandError` (branch esistente) → `error`. Test:
    `::test_git_create_branch_already_exists`.

### `git_commit(project, message, paths)` (write)

Commit di paths espliciti — mai `git commit -a`.

- Parametri:
  - `message: str` non vuoto.
  - `paths: list[str]` non vuota; ogni path validato con `resolve_within`
    e ridotto a path relativo alla root.
- Pipeline: `git add -- <paths>` → `git commit -m <msg> -- <paths>` →
  `git rev-parse HEAD`.
- Return: `{hash, short_hash, branch, paths}`.
- Errori:
  - `WriteNotAllowedError`, `PathSecurityError` → `denied`.
  - `CommitMessageError`, `CommitPathsError` → `error`. Test:
    `tests/test_tools_git.py::test_git_commit_paths_required`,
    `::test_git_commit_message_required`.
  - `GitCommandError` (paths senza modifiche) → `error`. Test:
    `::test_git_commit_no_changes_fails`.
- Test che il commit committa **solo** i path elencati (no -a implicito):
  `::test_git_commit_only_commits_listed_paths`.

### `git_push(project, remote="origin")` (write)

`git push <remote> HEAD:<branch>`. Push del branch corrente, mai
detached, mai forzato.

- Parametri:
  - `remote: str = "origin"` — validato con regex
    `^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$` (costante `_REMOTE_NAME_RE` in
    `tools/git.py`).
- Pre-condizioni:
  - `project.write_enabled = true`.
  - `project.allow_push = true` (gate aggiuntivo). Test:
    `tests/test_tools_git.py::test_git_push_requires_allow_push`,
    `::test_git_push_requires_write_enabled`.
- Backstop hardcoded: la costante `_FORBIDDEN_PUSH_FLAGS` in
  `tools/git.py` contiene `--force`, `-f`, `--mirror`, `--delete`, `-d`,
  `--all`, `--prune`, `--force-with-lease`. La signature attuale non
  permette di passarli, ma il check è difensivo per evoluzioni future.
- Return: `{remote, branch, stdout, stderr, stdout_truncated,
  stderr_truncated}`. Output troncato a `MAX_PUSH_OUTPUT_BYTES=64 KB`.
- Errori:
  - `WriteNotAllowedError` → `denied`.
  - `PushNotAllowedError` (`allow_push=false`) → `tool.git_push` /
    `denied` (mappatura specifica in `server._outcome_for_exception`).
  - `RemoteNameError` (regex remote fallita) → `error`. Test:
    `::test_git_push_invalid_remote_name`.
  - `GitCommandError` (HEAD detached, push fallito) → `error`.
- Smoke test reale verso bare repo locale:
  `::test_git_push_success_to_local_bare_remote`.

NON implementati di proposito (vedi `docs/devbox-bridge-brief.md`,
sezione "Git" del piano tool): `reset --hard`, `push --force`, `clean`,
`branch -D`. Non c'è nessuna versione "soft" — semplicemente non esistono
come tool.

## Esecuzione (4 tool)

Implementazione: `src/devbox_bridge/tools/execution.py`.
Tutti i tool exec richiedono `project.write_enabled = true`. Anche
`run_tests`/`run_lint`/`run_build` (rationale: pytest scrive
`.pytest_cache`, ruff `--fix` riscrive, build genera artefatti — vedi
`HANDOFF.md` "Tutti i tool exec gated da `write_enabled`"). Test:
`tests/test_tools_execution.py::test_run_command_write_disabled_raises`,
`::test_run_tests_write_disabled_raises`.

`subprocess.run` con lista args, `cwd=project_root`, `stdin=DEVNULL`, env
sanitizzato. `exit_code != 0` e timeout NON sollevano eccezione: outcome
legittimi (test rossi, build lenta). Differenza intenzionale dai tool
git. Test:
`tests/test_tools_execution.py::test_run_command_nonzero_exit_returns_response_no_exception`,
`::test_run_command_timeout_returns_response_no_exception`.

Schema response unico per i 4 tool:

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

`stdout`/`stderr` troncati a `MAX_OUTPUT_BYTES = 100 KB`. `timed_out=true`
implica `exit_code=-1`.

### `run_command(project, command, timeout=60)`

Comando arbitrario. Validazione **deny list + whitelist regex**.

- Parametri:
  - `command: str`.
  - `timeout: int = DEFAULT_RUN_COMMAND_TIMEOUT_SECONDS = 60`. Range
    `[1, MAX_EXEC_TIMEOUT_SECONDS=600]`.
- Validazione:
  1. `write_enabled` → `WriteNotAllowedError`.
  2. timeout in range → `TimeoutOutOfRangeError`. Test:
     `::test_run_command_timeout_out_of_range_raises`.
  3. `security.commands.check_command(command, project.command_whitelist)`:
     deny list (`rm -rf /`, `dd if=`, fork bomb, `curl|sh`,
     `shutdown`/`reboot`/`poweroff`/`init 0|6`,
     `systemctl poweroff/reboot/halt/emergency/rescue`, ecc.) + match
     `re.fullmatch` su almeno un pattern in `command_whitelist`. Test:
     `tests/test_command_whitelist.py::test_deny_rm_rf_root_with_permissive_whitelist`,
     `tests/test_tools_execution.py::test_run_command_not_in_whitelist_rejected`,
     `::test_run_command_deny_list_blocks_even_in_whitelist`.
  4. `argv[0]` risolto via `shutil.which` →
     `ExecutableNotFoundError` (path relativi tipo `./venv/bin/pytest`
     NON funzionano: `shutil.which` non tiene conto del cwd custom; usare
     binari nel PATH o path assoluti). Test:
     `::test_run_command_executable_not_found`,
     `::test_run_tests_relative_path_executable_raises`.

### `run_tests(project)` / `run_lint(project)` / `run_build(project)`

Eseguono rispettivamente `project.test_command` / `lint_command` /
`build_command` con timeout `DEFAULT_CONFIGURED_TIMEOUT_SECONDS=300s`.

- Validazione: `write_enabled` + comando configurato (non `null`) +
  **solo** deny list (whitelist bypassata). Razionale: i comandi sono
  amministrativamente autorizzati perché stanno in `config.yaml`, SoT del
  progetto. La deny list resta come fail-secure contro errori tipo
  `test_command: "pytest && rm -rf /etc"`. Implementazione esposta come
  `security.commands.check_deny_list` (split esplicito, non
  side-effect di whitelist vuota). Test:
  `tests/test_tools_execution.py::test_run_tests_bypasses_whitelist`,
  `::test_run_tests_deny_list_blocks_configured_command`.
- Errori:
  - `WriteNotAllowedError` → `denied`.
  - `NoCommandConfiguredError` se il `*_command` è `null`. Test:
    `::test_run_tests_no_command_configured_raises`,
    `::test_run_lint_no_command_configured_raises`,
    `::test_run_build_no_command_configured_raises`.
  - `CommandRejectedError` (deny list) → `command.rejected` / `denied`.
  - `ExecutableNotFoundError` → `error`.

### Errori → event/outcome

| Eccezione                  | event                | outcome   |
|----------------------------|----------------------|-----------|
| `WriteNotAllowedError`     | `path.rejected`      | `denied`  |
| `CommandRejectedError`     | `command.rejected`   | `denied`  |
| `NoCommandConfiguredError` | `tool.<name>`        | `error`   |
| `ExecutableNotFoundError`  | `tool.<name>`        | `error`   |
| `TimeoutOutOfRangeError`   | `tool.run_command`   | `error`   |

Riferimento codice: `server.py::_event_for_tool`,
`::_outcome_for_exception`.

### `outcome_detail` audit (sub-outcome subprocess)

Solo per i tool exec, popolato su `outcome="success"`:

- `completed` — `exit_code == 0`.
- `nonzero_exit` — `exit_code != 0` e non timeout.
- `timed_out` — subprocess interrotto per timeout.

Non promosso a `outcome="error"` perché il bridge ha eseguito il
subprocess correttamente; il dettaglio descrive cosa è successo nel
processo figlio. Implementato in `server._outcome_detail_from_result`.
Test: `tests/test_server.py` (audit success con `outcome_detail`).

### `args_summary` audit per tool exec

- `command` troncato a `COMMAND_AUDIT_TRUNCATE_CHARS=500` char +
  `...[truncated]` se più lungo (anti log poisoning, costante
  `COMMAND_AUDIT_TRUNCATE_CHARS` in `server.py`).
- `stdout`/`stderr` riassunti via `audit.summarize_command_output`
  (head 500ch + tail 500ch + `total_sha8` + `total_bytes` + `truncated`).
- `exit_code`, `duration_ms`, `timed_out`, `stdout_truncated`,
  `stderr_truncated` propagati come field di sintesi.

## Sistema (4 tool)

Implementazione: `src/devbox_bridge/tools/system.py`. Tutti read-only.
`subprocess.run` con `cwd=None` (system-wide), env sanitizzato,
`stdin=DEVNULL`, `timeout=SYSTEM_TIMEOUT_SECONDS=30s`.

Nessun `write_enabled` requirement: questi tool guardano lo stato della
macchina, non i progetti. Per la semantica fail-secure delle whitelist
(`system:` omesso vs lista esplicitamente `[]`) vedi `SECURITY.md →
Whitelist system tools`.

### `get_system_info()`

Aggregato read-only di info sistema. Resiliente a fallimenti parziali: se
un sub-step fallisce (binario assente, `/proc` non leggibile), il campo
corrispondente resta al default ma il tool NON solleva. Test:
`tests/test_tools_system.py::test_get_system_info_resilient_to_df_failure`,
`::test_get_system_info_resilient_to_uname_failure`,
`::test_get_system_info_resilient_to_subprocess_error`.

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

Schema:

- `uptime_seconds: int` (parte intera di `/proc/uptime`).
- `memory_bytes` in **byte** (kB di `/proc/meminfo` × 1024 al momento
  della lettura; più chiaro di `memory_kb` ambiguo). Test:
  `::test_get_system_info_memory_in_bytes`.
- `disk[]` campi **deliberatamente human-readable** (`df -h`):
  `size`/`used`/`avail` come stringhe `"98G"`, `use_pct` come `"15%"`.
  **Non parsare numericamente.** Se in futuro servono byte raw verrà
  aggiunto un `disk_bytes` separato.
- Audit: read.

### `list_systemd_services(name_filter=None)`

`systemctl list-units --type=service --all --no-pager --plain --no-legend`
filtrato per substring sul nome unit.

- `name_filter`:
  - `None` → usa `system.systemd_filter_default` di config (default
    `"devbox-"`).
  - stringa non vuota → validata con regex
    `^[A-Za-z0-9._@:-]{1,64}$` (defense-in-depth contro injection,
    anche se `subprocess.run` è `shell=False`). Test:
    `tests/test_tools_system.py::test_list_systemd_services_filter_pattern_injection_rejected`.
  - stringa vuota → nessun filtro (tutte le service unit). Test:
    `::test_list_systemd_services_empty_filter_returns_all`.
- Return:

  ```json
  {
    "filter": "devbox-",
    "exit_code": 0,
    "services": [
      {"unit": "devbox-bridge.service", "load": "loaded",
       "active": "active", "sub": "running", "description": "..."}
    ]
  }
  ```
- Errori: `FilterPatternError` → `error`. `SystemctlNotAvailableError`
  → `error`.

### `tail_log(path, lines=100)`

`tail -n <lines> <path>` su un file dentro `system.log_paths_whitelist`.

- Parametri:
  - `path: str` — assoluto, esistente.
  - `lines: int = 100` — range `[1, MAX_LOG_LINES=5000]`.
- Validazione (in ordine):
  1. `lines` in range → `LinesOutOfRangeError`. Test:
     `tests/test_tools_system.py::test_tail_log_lines_out_of_range`.
  2. `resolve_within_any(path, system.log_paths_whitelist)`:
     - assoluto, esistente, dentro almeno un root della whitelist.
     - Symlink risolti **prima del confronto** (strict=True) → un symlink
       dentro la whitelist che esce viene rifiutato. Test:
       `::test_tail_log_symlink_escaping_whitelist_rejected`.
     - Path relativi rifiutati. Test:
       `::test_tail_log_relative_path_rejected`.
     - Whitelist `[]` blocca tutto (fail-secure). Test:
       `::test_tail_log_empty_whitelist_blocks_everything`.
  3. `tail` disponibile nel PATH → `TailNotAvailableError`.
- Return:

  ```json
  {
    "source": "/var/log/devbox-bridge/audit.log",
    "lines_requested": 100,
    "exit_code": 0,
    "content": "...",
    "content_truncated": false
  }
  ```
- Output troncato a `MAX_LOG_OUTPUT_BYTES = 512 KB` (≈ metà context
  window 200K-token). Test:
  `::test_tail_log_output_truncated_at_max_bytes`.
- Errori → audit:
  - `LogPathNotAllowedError` → `path.rejected` / `denied`. Test:
    `::test_tail_log_path_not_in_whitelist_rejected`,
    `::test_tail_log_path_traversal_rejected`.
  - `LogPathNotFoundError` → `tool.tail_log` / `error`. Test:
    `::test_tail_log_nonexistent_raises_log_path_not_found`.

### `read_journalctl(unit, lines=100)`

`journalctl -u <unit> -n <lines> --no-pager` per unit in
`system.systemd_unit_whitelist`.

- Parametri:
  - `unit: str` — doppio gate:
    1. regex `^[A-Za-z0-9._@:-]{1,64}$` (defense-in-depth). Test:
       `tests/test_tools_system.py::test_read_journalctl_unit_invalid_regex_rejected`.
    2. appartenenza a `system.systemd_unit_whitelist`. Test:
       `::test_read_journalctl_unit_not_in_whitelist_rejected`.
  - `lines: int = 100` — `[1, MAX_LOG_LINES=5000]`.
- Return: stesso schema di `tail_log` con `source: "journalctl:<unit>"`.
- Errori → audit:
  - `JournalctlUnitNotAllowedError` → `tool.read_journalctl` / `denied`.
  - `LinesOutOfRangeError`, `JournalctlNotAvailableError` → `error`.
- Permessi journal: l'utente del bridge deve essere in
  `systemd-journal` (default) o `adm`. `deploy/install.sh` aggiunge il
  service user a `systemd-journal` (least privilege rispetto ad `adm` che
  esporrebbe anche `/var/log/syslog` ecc.). Vedi `SECURITY.md` e
  `HANDOFF.md` "Permessi journal".

## Mappa errori → event/outcome (riepilogo)

Mappatura applicata da `server._event_for_tool` /
`_outcome_for_exception`. Il `tool.<name>` di default vale tranne dove
indicato.

| Eccezione                          | event                  | outcome  |
|------------------------------------|------------------------|----------|
| `PathSecurityError`                | `path.rejected`        | `denied` |
| `GlobSecurityError`                | `path.rejected`        | `denied` |
| `WriteNotAllowedError`             | `path.rejected`        | `denied` |
| `LogPathNotAllowedError`           | `path.rejected`        | `denied` |
| `CommandRejectedError`             | `command.rejected`     | `denied` |
| `PushNotAllowedError`              | `tool.git_push`        | `denied` |
| `JournalctlUnitNotAllowedError`    | `tool.read_journalctl` | `denied` |
| `BinaryFileError`, `FileTooLarge`  | `tool.<name>`          | `error`  |
| `BranchNameError`, `RemoteName...` | `tool.<name>`          | `error`  |
| `GitCommandError`,`NotARepository` | `tool.<name>`          | `error`  |
| `NoCommandConfiguredError`         | `tool.<name>`          | `error`  |
| `ExecutableNotFoundError`          | `tool.<name>`          | `error`  |
| `TimeoutOutOfRangeError`           | `tool.run_command`     | `error`  |
| `LinesOutOfRangeError`             | `tool.<name>`          | `error`  |
| `FilterPatternError`               | `tool.list_systemd...` | `error`  |
| `*NotAvailableError` (binari)      | `tool.<name>`          | `error`  |
| success                            | `tool.<name>`          | `success`|

`outcome="denied"` e `"error"` sono **sempre** auditati, anche per i
read tool (override di `audit_reads`). Vedi `SECURITY.md → Audit logging`
e `audit.AuditLogger.log`.

## Esempio end-to-end

### Curl

```bash
TOKEN="<plain token>"
curl -sS -X POST http://127.0.0.1:8765/mcp \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/call",
    "params": {
      "name": "list_projects",
      "arguments": {}
    }
  }'
```

### FastMCP client Python

```python
from fastmcp import Client

async with Client(
    "http://127.0.0.1:8765/mcp",
    headers={"Authorization": f"Bearer {TOKEN}"},
) as client:
    result = await client.call_tool("read_file", {
        "project": "devbox-bridge",
        "rel_path": "README.md",
    })
    print(result.data["content"][:200])
```

### Risposta attesa (estratto)

```json
{
  "path": "README.md",
  "bytes": 1234,
  "encoding": "utf-8",
  "content_sha8": "deadbeef",
  "content": "# devbox-bridge\n..."
}
```
