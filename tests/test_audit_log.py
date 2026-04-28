"""Test audit log — audit.py.

Casi minimi:
  - write_file logga su audit.log con tool/args/exit/duration
  - git_commit logga
  - run_command logga
  - read tool (read_file, list_directory) NON loggano (audit è solo per write/exec)
  - args sanitizzati: token/password/key non finiscono in log
"""

import pytest

pytest.skip("placeholder — implementazione nello step 5", allow_module_level=True)
