"""Tool MCP — esecuzione test/lint/build/comandi arbitrari.

TODO (step 9):
  - run_tests(project) -> CommandResult
  - run_lint(project) -> CommandResult
  - run_build(project) -> CommandResult
  - run_command(project, command: str, timeout: int = 60) -> CommandResult

  Tutti:
    - subprocess.run con lista args (shlex.split), MAI shell=True
    - timeout obbligatorio, max 600s (clamp)
    - cwd forzato alla project root
    - env via security.env.sanitize_env(... passthrough=project.env_passthrough)
    - stdout/stderr troncati a 100KB con flag `truncated: true`
    - audit.log_action() per ogni run
"""

# placeholder — implementazione nello step 9
