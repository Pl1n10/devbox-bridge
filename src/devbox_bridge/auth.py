"""Bearer token auth + rate limit.

Logica pura — l'integrazione ASGI/FastMCP è in server.py.

Threat model di questo modulo (vedi anche docs/SECURITY.md):
  - Token confrontato a tempo costante via hmac.compare_digest su digest hex.
  - Stesso errore (AuthFailed) per token mancante o invalido — niente info disclosure.
  - Token plain mai loggato. Identificatore nei log = sha256(token)[:8].
  - Rate limit applicato SOLO dopo auth success: un attaccante non può consumare
    il budget di un token valido sparando token random.
  - Rate limit in-memory: si resetta al restart, è per-worker (vedi SECURITY.md).
"""

from __future__ import annotations

import hashlib
import hmac
import re
import time
from collections import defaultdict, deque
from pathlib import Path
from threading import Lock

import structlog

logger = structlog.get_logger("devbox_bridge.auth")

DEFAULT_RATE_LIMIT_PER_MINUTE = 60
RATE_LIMIT_WINDOW_SECONDS = 60.0
_HEX_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")


class AuthError(Exception):
    """Base — generica, non rivela motivo specifico al client."""


class AuthFailed(AuthError):
    """Token mancante o invalido. Il chiamante traduce in 401 generico."""


class RateLimitExceeded(AuthError):
    """Troppe chiamate per questo token. 429."""


def _load_token_hash(path: Path) -> str:
    """Legge sha256 hex dal file. Solleva ValueError con messaggio leggibile su errore."""
    try:
        content = path.read_text(encoding="utf-8").strip()
    except FileNotFoundError as e:
        raise ValueError(f"token hash file '{path}' non trovato") from e
    except PermissionError as e:
        raise ValueError(
            f"token hash file '{path}' non leggibile (permission denied). "
            f"Verifica che l'utente del processo abbia accesso."
        ) from e
    except OSError as e:
        raise ValueError(f"errore lettura token hash file '{path}': {e}") from e
    if not _HEX_SHA256_RE.fullmatch(content):
        raise ValueError(
            f"token hash file '{path}' non contiene un sha256 hex valido (64 char hex attesi)"
        )
    return content.lower()


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def verify_token(provided: str, expected_hex: str) -> bool:
    """Confronto a tempo costante tra sha256(provided) e expected_hex."""
    actual_hex = _hash_token(provided)
    return hmac.compare_digest(actual_hex, expected_hex)


def token_log_id(token: str | None) -> str:
    """Identificatore per log/audit. NON rivela il token plain.

    - None / vuoto → '(none)'
    - altrimenti → sha256(token)[:8]
    """
    if not token:
        return "(none)"
    return _hash_token(token)[:8]


class RateLimiter:
    """Sliding window rate limiter per token_id.

    TODO(scale): per ora dict[token_id, deque] cresce illimitato. Con N>>1 token
    convertire in bounded LRU (es. cachetools.TTLCache o lru_cache esplicita).
    Con il setup attuale (1 token) è zero problemi — e dato che il limiter è
    chiamato solo dopo auth success, la chiave è sempre un token_id valido.
    """

    def __init__(self, max_per_minute: int = DEFAULT_RATE_LIMIT_PER_MINUTE) -> None:
        if max_per_minute < 1:
            raise ValueError(f"max_per_minute deve essere >= 1, ho {max_per_minute}")
        self.max_per_minute = max_per_minute
        self._buckets: dict[str, deque[float]] = defaultdict(deque)
        self._lock = Lock()

    def check(self, token_id: str, *, now: float | None = None) -> int:
        """Solleva RateLimitExceeded se il bucket è pieno; altrimenti registra hit.

        Ritorna il count attuale nel bucket (utile per logging).
        Il parametro `now` serve solo ai test per determinismo.
        """
        if now is None:
            now = time.monotonic()
        cutoff = now - RATE_LIMIT_WINDOW_SECONDS
        with self._lock:
            bucket = self._buckets[token_id]
            while bucket and bucket[0] < cutoff:
                bucket.popleft()
            if len(bucket) >= self.max_per_minute:
                raise RateLimitExceeded(
                    f"rate limit superato: {len(bucket)} hits in {RATE_LIMIT_WINDOW_SECONDS}s"
                )
            bucket.append(now)
            return len(bucket)


class Authenticator:
    """Orchestratore: carica hash al boot, valida token, applica rate limit."""

    def __init__(
        self,
        token_hash_file: Path,
        rate_limit_per_minute: int = DEFAULT_RATE_LIMIT_PER_MINUTE,
    ) -> None:
        self._expected_hash = _load_token_hash(token_hash_file)
        self._rate_limiter = RateLimiter(max_per_minute=rate_limit_per_minute)

    def check(
        self,
        provided_token: str | None,
        *,
        client_ip: str | None = None,
        now: float | None = None,
    ) -> str:
        """Valida token e applica rate limit. Ritorna token_id se ok."""
        log_id = token_log_id(provided_token)

        if not provided_token:
            logger.warning(
                "auth.failed",
                reason="missing_token",
                token_id=log_id,
                client_ip=client_ip,
            )
            raise AuthFailed()

        if not verify_token(provided_token, self._expected_hash):
            logger.warning(
                "auth.failed",
                reason="invalid_token",
                token_id=log_id,
                client_ip=client_ip,
            )
            raise AuthFailed()

        try:
            self._rate_limiter.check(log_id, now=now)
        except RateLimitExceeded:
            logger.warning(
                "auth.rate_limited",
                token_id=log_id,
                client_ip=client_ip,
                window_seconds=RATE_LIMIT_WINDOW_SECONDS,
                limit=self._rate_limiter.max_per_minute,
            )
            raise

        # No log su success per evitare rumore. L'audit log dei tool write
        # registra le azioni effettive (step 5).
        return log_id
