"""Test tool git.

Setup: tmp_path con `git init`, qualche commit, file modificato.

Casi minimi:
  - git_status su repo pulito
  - git_status con modifiche unstaged + staged
  - git_diff testuale
  - git_log con limit
  - git_branch_current
  - git_create_branch crea branch e ci si sposta
  - git_commit fallisce se paths vuoti (no -a implicito)
  - git_push respinto se allow_push=false
"""

import pytest

pytest.skip("placeholder — implementazione nello step 8", allow_module_level=True)
