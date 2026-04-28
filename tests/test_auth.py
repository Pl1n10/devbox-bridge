"""Test auth bearer + rate limit — auth.py."""

from __future__ import annotations

import hashlib
import os
import sys
from pathlib import Path

import pytest
import structlog

from devbox_bridge.auth import (
    DEFAULT_RATE_LIMIT_PER_MINUTE,
    Authenticator,
    AuthFailed,
    RateLimiter,
    RateLimitExceeded,
    _hash_token,
    _load_token_hash,
    token_log_id,
    verify_token,
)

VALID_TOKEN = "s3cr3t-test-token-do-not-use-in-prod"
VALID_HASH = hashlib.sha256(VALID_TOKEN.encode()).hexdigest()


@pytest.fixture
def hash_file(tmp_path: Path) -> Path:
    f = tmp_path / "token.sha256"
    f.write_text(VALID_HASH + "\n", encoding="utf-8")
    return f


# --- _load_token_hash ---


def test_load_token_hash_valid(hash_file: Path) -> None:
    assert _load_token_hash(hash_file) == VALID_HASH


def test_load_token_hash_strips_whitespace(tmp_path: Path) -> None:
    f = tmp_path / "h"
    f.write_text(f"  {VALID_HASH}  \n", encoding="utf-8")
    assert _load_token_hash(f) == VALID_HASH


def test_load_token_hash_lowercases(tmp_path: Path) -> None:
    f = tmp_path / "h"
    f.write_text(VALID_HASH.upper(), encoding="utf-8")
    assert _load_token_hash(f) == VALID_HASH


def test_load_token_hash_missing_file(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="non trovato"):
        _load_token_hash(tmp_path / "missing.sha256")


def test_load_token_hash_wrong_length(tmp_path: Path) -> None:
    f = tmp_path / "h"
    f.write_text("abc123", encoding="utf-8")
    with pytest.raises(ValueError, match="sha256 hex"):
        _load_token_hash(f)


def test_load_token_hash_non_hex(tmp_path: Path) -> None:
    f = tmp_path / "h"
    f.write_text("z" * 64, encoding="utf-8")
    with pytest.raises(ValueError, match="sha256 hex"):
        _load_token_hash(f)


@pytest.mark.skipif(
    sys.platform == "win32" or (hasattr(os, "geteuid") and os.geteuid() == 0),
    reason="permission denied test richiede non-root su Unix",
)
def test_load_token_hash_permission_denied(tmp_path: Path) -> None:
    """Chmod sbagliato sul file token in prod è il caso più probabile: msg diagnostico chiaro."""
    f = tmp_path / "token.sha256"
    f.write_text(VALID_HASH, encoding="utf-8")
    f.chmod(0o000)
    try:
        with pytest.raises(ValueError, match="permission denied"):
            _load_token_hash(f)
    finally:
        # restore per il cleanup di tmp_path
        f.chmod(0o644)


# --- verify_token ---


def test_verify_token_correct() -> None:
    assert verify_token(VALID_TOKEN, VALID_HASH) is True


def test_verify_token_wrong() -> None:
    assert verify_token("other", VALID_HASH) is False


def test_verify_token_empty() -> None:
    assert verify_token("", VALID_HASH) is False


# --- token_log_id (no plain leak) ---


def test_token_log_id_none() -> None:
    assert token_log_id(None) == "(none)"


def test_token_log_id_empty() -> None:
    assert token_log_id("") == "(none)"


def test_token_log_id_deterministic() -> None:
    assert token_log_id(VALID_TOKEN) == token_log_id(VALID_TOKEN)
    assert len(token_log_id(VALID_TOKEN)) == 8


def test_token_log_id_does_not_leak_plain() -> None:
    log_id = token_log_id(VALID_TOKEN)
    assert VALID_TOKEN not in log_id
    assert log_id != VALID_TOKEN[:8]


# --- RateLimiter ---


def test_rate_limiter_allows_under_limit() -> None:
    rl = RateLimiter(max_per_minute=5)
    for _ in range(5):
        rl.check("tok", now=0.0)


def test_rate_limiter_blocks_over_limit() -> None:
    rl = RateLimiter(max_per_minute=3)
    for _ in range(3):
        rl.check("tok", now=0.0)
    with pytest.raises(RateLimitExceeded):
        rl.check("tok", now=0.0)


def test_rate_limiter_sliding_window_decay() -> None:
    rl = RateLimiter(max_per_minute=2)
    rl.check("tok", now=0.0)
    rl.check("tok", now=10.0)
    with pytest.raises(RateLimitExceeded):
        rl.check("tok", now=20.0)
    # Dopo 60s+ il primo hit esce dalla finestra
    rl.check("tok", now=61.0)


def test_rate_limiter_isolated_per_token() -> None:
    rl = RateLimiter(max_per_minute=2)
    rl.check("a", now=0.0)
    rl.check("a", now=0.0)
    # 'b' non è impattato dalla saturazione di 'a'
    rl.check("b", now=0.0)
    rl.check("b", now=0.0)
    with pytest.raises(RateLimitExceeded):
        rl.check("a", now=0.0)


def test_rate_limiter_invalid_max() -> None:
    with pytest.raises(ValueError):
        RateLimiter(max_per_minute=0)


# --- Authenticator ---


def test_authenticator_valid_token(hash_file: Path) -> None:
    auth = Authenticator(hash_file)
    log_id = auth.check(VALID_TOKEN, client_ip="127.0.0.1")
    assert log_id == _hash_token(VALID_TOKEN)[:8]


def test_authenticator_invalid_token_raises_authfailed(hash_file: Path) -> None:
    auth = Authenticator(hash_file)
    with pytest.raises(AuthFailed):
        auth.check("wrong-token")


def test_authenticator_missing_token_same_error_as_invalid(hash_file: Path) -> None:
    """Token mancante e token invalido → stesso AuthFailed (no info disclosure)."""
    auth = Authenticator(hash_file)
    with pytest.raises(AuthFailed):
        auth.check(None)
    with pytest.raises(AuthFailed):
        auth.check("")


def test_authenticator_rate_limit_only_after_success(hash_file: Path) -> None:
    """Token invalidi NON consumano il budget rate limit."""
    auth = Authenticator(hash_file, rate_limit_per_minute=3)
    # 100 token invalidi non devono saturare il limite
    for _ in range(100):
        with pytest.raises(AuthFailed):
            auth.check("invalid")
    # Token valido può ancora fare 3 chiamate
    for i in range(3):
        auth.check(VALID_TOKEN, now=float(i))
    with pytest.raises(RateLimitExceeded):
        auth.check(VALID_TOKEN, now=3.0)


def test_authenticator_default_rate_limit() -> None:
    assert DEFAULT_RATE_LIMIT_PER_MINUTE == 60


def test_authenticator_handles_uppercase_hash_file(tmp_path: Path) -> None:
    """Pipeline end-to-end: hash file in uppercase deve normalizzare e validare il token."""
    f = tmp_path / "token.sha256"
    f.write_text(VALID_HASH.upper(), encoding="utf-8")
    auth = Authenticator(f)
    log_id = auth.check(VALID_TOKEN)
    assert log_id == _hash_token(VALID_TOKEN)[:8]


def test_authenticator_logs_no_plain_token(
    hash_file: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Sanity guard: il token plain non deve mai apparire in stdout/stderr."""
    structlog.reset_defaults()  # default config logga su stdout
    auth = Authenticator(hash_file)
    bad_token = VALID_TOKEN + "wrong-suffix-tail"
    with pytest.raises(AuthFailed):
        auth.check(bad_token)
    captured = capsys.readouterr()
    combined = captured.out + captured.err
    assert bad_token not in combined
    assert VALID_TOKEN not in combined
