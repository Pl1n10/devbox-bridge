# TOOLS — Reference dei tool MCP esposti

> Stato step 7: i tool filesystem sono registrati nel server FastMCP e
> disponibili su HTTP `/mcp`. Gli altri gruppi sono ancora placeholder.

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

Placeholder step 8:

- `git_status(project)` — read
- `git_diff(project, staged=False, path=None)` — read
- `git_log(project, limit=20)` — read
- `git_branch_current(project)` — read
- `git_create_branch(project, name)` — **write**
- `git_commit(project, message, paths)` — **write**
- `git_push(project, remote='origin')` — **write**, richiede `allow_push: true`

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
