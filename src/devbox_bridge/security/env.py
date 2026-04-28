"""Sanitizer dell'environment passato ai subprocess.

TODO (step 4):
  - SECRET_PATTERNS = ['^AWS_.*$', '.*_TOKEN$', '.*_SECRET$', '.*_KEY$', ...]
  - sanitize_env(parent_env: Mapping[str, str], passthrough: list[str]) -> dict[str, str]
      - parte da parent_env
      - rimuove tutto ciò che matcha SECRET_PATTERNS
      - reintroduce SOLO le chiavi in `passthrough` (whitelist esplicita per progetto)
      - mantiene PATH, HOME, LANG, LC_*, SHELL minimi necessari
"""

# placeholder — implementazione nello step 4
