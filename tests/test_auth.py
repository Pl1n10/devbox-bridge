"""Test auth bearer + rate limit — auth.py.

Casi minimi:
  - token valido → ok
  - token invalido → 401
  - header mancante → 401
  - confronto a tempo costante (hmac.compare_digest)
  - rate limit: 60 chiamate/min ok, la 61° → 429
  - rate limit per-token (token diversi non si influenzano)
"""

import pytest

pytest.skip("placeholder — implementazione nello step 3", allow_module_level=True)
