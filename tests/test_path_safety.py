"""Test path traversal — security/paths.py.

Casi minimi richiesti dal brief:
  - '..' che tenta di uscire dalla project root
  - symlink che puntano fuori dalla project root
  - path assoluti maliziosi (es. '/etc/passwd')
  - path con '..' annidati ('a/b/../../../../etc/passwd')
  - path validi devono passare
"""

import pytest

pytest.skip("placeholder — implementazione nello step 4", allow_module_level=True)
