"""Path traversal guard.

TODO (step 4):
  - resolve_within(project_root: Path, candidate: str | Path) -> Path
    risolve il candidato e raise PathSecurityError se cade fuori da project_root
    (test esplicito per: '..', symlink che escono, path assoluti maliziosi).
  - resolve_project_path(config: AppConfig, project: str, path: str) -> Path
    prende il root dal config e applica resolve_within.
"""


class PathSecurityError(ValueError):
    """Tentativo di accedere a un path fuori dalla whitelist progetti."""


# placeholder — implementazione nello step 4
