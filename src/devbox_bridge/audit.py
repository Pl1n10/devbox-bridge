"""Audit logger separato per azioni che modificano stato.

TODO (step 5):
  - log_action(tool: str, args: dict, exit_code: int | None, duration_ms: float)
  - sanitize_args() rimuove valori che sembrano secret (token, password, key)
  - scrive su <log_dir>/audit.log con rotazione giornaliera
  - format JSON: {ts, tool, args, exit_code, duration_ms, project, user_token_hash_prefix}
"""

# placeholder — implementazione nello step 5
