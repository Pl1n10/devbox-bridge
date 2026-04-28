"""Bearer token auth + rate limit.

TODO (step 3):
  - verify_token(provided: str, hash_file_path: Path) -> bool con hmac.compare_digest
  - RateLimiter(max_per_minute=60) sliding window per token
  - middleware/dependency FastMCP che valida header Authorization e applica il limit
  - 401 se token mancante/errato, 429 se rate limit superato
"""

# placeholder — implementazione nello step 3
