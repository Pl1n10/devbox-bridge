"""Caricamento e validazione di config.yaml.

TODO (step 2): definire i pydantic model:
  - ServerConfig(bind, log_level, log_dir)
  - AuthConfig(token_hash_file)
  - ProjectConfig(path, write_enabled, allow_push,
                  test_command, lint_command, build_command,
                  command_whitelist: list[str], env_passthrough: list[str])
  - AppConfig(server, auth, projects: dict[str, ProjectConfig])
e una funzione `load_config(path: Path) -> AppConfig` che valida (path esistente, ecc.).
"""

# placeholder — implementazione nello step 2
