# TOOLS — Reference dei tool MCP esposti

> **Skeleton — popolare nello step 12 con esempi di chiamata e output reali.**

## Filesystem

- `list_projects()` — read
- `read_file(project, path)` — read
- `list_directory(project, path)` — read
- `search_files(project, pattern, glob)` — read (rg wrapper)
- `write_file(project, path, content, create=False)` — **write**
- `apply_patch(project, path, old, new)` — **write**

## Git

- `git_status(project)` — read
- `git_diff(project, staged=False, path=None)` — read
- `git_log(project, limit=20)` — read
- `git_branch_current(project)` — read
- `git_create_branch(project, name)` — **write**
- `git_commit(project, message, paths)` — **write**
- `git_push(project, remote='origin')` — **write**, richiede `allow_push: true`

## Esecuzione

- `run_tests(project)` — exec
- `run_lint(project)` — exec
- `run_build(project)` — exec
- `run_command(project, command, timeout=60)` — exec, whitelist obbligatoria

## Sistema

- `get_system_info()` — read
- `list_systemd_services(filter='devbox-')` — read
- `tail_log(path, lines=100)` — read

> Per ognuno: schema input/output e un esempio reale dopo l'implementazione.
