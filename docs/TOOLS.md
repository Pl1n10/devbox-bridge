# TOOLS — Reference dei tool MCP esposti

> Stato step 8: i tool filesystem e git sono registrati nel server FastMCP
> e disponibili su HTTP `/mcp`. Esecuzione e sistema sono ancora placeholder.

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

Placeholder step 9:

- `run_tests(project)` — exec
- `run_lint(project)` — exec
- `run_build(project)` — exec
- `run_command(project, command, timeout=60)` — exec, whitelist obbligatoria

## Sistema

Placeholder step 10:

- `get_system_info()` — read
- `list_systemd_services(filter='devbox-')` — read
- `tail_log(path, lines=100)` — read
