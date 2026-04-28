"""Test whitelist regex + deny list — security/commands.py.

Casi minimi:
  - whitelist match esatto (fullmatch, non substring)
  - whitelist no-match → reject
  - deny list precedence: 'rm -rf /' bloccato anche se whitelist permissiva
  - 'curl ... | sh' bloccato
  - argomenti con spazi gestiti (shlex.split)
"""

import pytest

pytest.skip("placeholder — implementazione nello step 4", allow_module_level=True)
