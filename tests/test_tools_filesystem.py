"""Test tool filesystem.

Casi minimi:
  - list_projects ritorna i progetti dal config
  - read_file su file esistente
  - read_file su path traversal → PathSecurityError
  - list_directory skip node_modules / .git / __pycache__ / .venv / dist / build
  - search_files (rg wrapper) con pattern banale
  - write_file solo se progetto write_enabled, altrimenti reject
  - apply_patch con `old` non univoco → fail
"""

import pytest

pytest.skip("placeholder — implementazione nello step 6", allow_module_level=True)
