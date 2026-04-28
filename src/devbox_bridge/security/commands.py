"""Command whitelist + deny list hardcoded.

TODO (step 4):
  - DENY_PATTERNS: regex hardcoded per costrutti distruttivi:
      rm -rf, dd if=, mkfs, > /dev/, fork bomb ':(){ :|:& };:',
      'curl ... | (sh|bash)', 'wget ... | (sh|bash)'
  - is_command_allowed(command: str, whitelist: list[str]) -> bool
      1) prima passa per DENY_PATTERNS → False
      2) poi controlla che fullmatch su almeno una whitelist
  - parse_command_argv(command: str) -> list[str] usa shlex.split
"""


class CommandRejectedError(ValueError):
    """Comando bloccato dalla deny list o non in whitelist."""


# placeholder — implementazione nello step 4
