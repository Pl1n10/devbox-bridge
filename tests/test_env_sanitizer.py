"""Test env sanitizer — security/env.py."""

from __future__ import annotations

import structlog.testing

from devbox_bridge.security.env import sanitize_env


def test_drops_all_secrets_by_default() -> None:
    parent = {
        "AWS_ACCESS_KEY_ID": "x",
        "AWS_SECRET_ACCESS_KEY": "y",
        "GITHUB_TOKEN": "ghp_xxx",
        "OPENAI_API_KEY": "sk-xxx",
        "MY_PASSWORD": "p",
        "FOO_SECRET": "s",
        "BAR_KEY": "k",
        "PATH": "/usr/bin",
        "HOME": "/home/x",
    }
    out = sanitize_env(parent)
    assert "AWS_ACCESS_KEY_ID" not in out
    assert "GITHUB_TOKEN" not in out
    assert "OPENAI_API_KEY" not in out
    assert "MY_PASSWORD" not in out
    assert "FOO_SECRET" not in out
    assert "BAR_KEY" not in out
    assert out["PATH"] == "/usr/bin"
    assert out["HOME"] == "/home/x"


def test_passthrough_overrides_deny() -> None:
    parent = {"DATABASE_URL_TEST": "postgres://x", "PATH": "/usr/bin"}
    out = sanitize_env(parent, passthrough=["DATABASE_URL_TEST"])
    assert out["DATABASE_URL_TEST"] == "postgres://x"


def test_passthrough_can_override_secret_pattern() -> None:
    """Override esplicito: se l'utente mette FOO_KEY in passthrough, lo vuole."""
    parent = {"FOO_KEY": "value"}
    out = sanitize_env(parent, passthrough=["FOO_KEY"])
    assert out["FOO_KEY"] == "value"


def test_unknown_random_var_dropped() -> None:
    """Whitelist mode: variabili non-infra e non-passthrough vengono droppate
    anche se non matchano nessun secret pattern."""
    parent = {"RANDOM_VAR": "x", "PATH": "/usr/bin"}
    out = sanitize_env(parent)
    assert "RANDOM_VAR" not in out


def test_ld_preload_dropped_even_if_in_parent() -> None:
    """LD_PRELOAD non è in _INFRA_VARS: deve essere dropped a meno di passthrough."""
    parent = {"LD_PRELOAD": "/tmp/evil.so", "PATH": "/usr/bin"}
    out = sanitize_env(parent)
    assert "LD_PRELOAD" not in out


def test_pythonpath_dropped_even_if_in_parent() -> None:
    parent = {"PYTHONPATH": "/tmp/evil", "PATH": "/usr/bin"}
    out = sanitize_env(parent)
    assert "PYTHONPATH" not in out


def test_passthrough_missing_in_parent_silent() -> None:
    parent = {"PATH": "/usr/bin"}
    out = sanitize_env(parent, passthrough=["MISSING_VAR"])
    assert "MISSING_VAR" not in out
    assert out["PATH"] == "/usr/bin"


def test_locale_lang_preserved() -> None:
    parent = {"LANG": "it_IT.UTF-8", "PATH": "/usr/bin"}
    out = sanitize_env(parent)
    assert out["LANG"] == "it_IT.UTF-8"


def test_lc_pattern_vars_preserved() -> None:
    """LC_* (POSIX) coperti dal pattern, non solo da set esplicito."""
    parent = {
        "LC_ALL": "C",
        "LC_TIME": "it_IT.UTF-8",
        "LC_NUMERIC": "C",
        "LC_MESSAGES": "en_US.UTF-8",
        "LC_MONETARY": "it_IT.UTF-8",
        "PATH": "/usr/bin",
    }
    out = sanitize_env(parent)
    assert out["LC_ALL"] == "C"
    assert out["LC_TIME"] == "it_IT.UTF-8"
    assert out["LC_NUMERIC"] == "C"
    assert out["LC_MESSAGES"] == "en_US.UTF-8"
    assert out["LC_MONETARY"] == "it_IT.UTF-8"


def test_lc_pattern_does_not_match_random_lc_prefix() -> None:
    """Il pattern LC_* non deve matchare LCD_DISPLAY o roba simile."""
    parent = {"LCD_DISPLAY": "value", "PATH": "/usr/bin"}
    out = sanitize_env(parent)
    assert "LCD_DISPLAY" not in out


def test_passthrough_secret_match_logs_warning() -> None:
    """Warning per audit quando un passthrough matcha un secret pattern."""
    parent = {"GITHUB_TOKEN": "ghp_xxx"}
    with structlog.testing.capture_logs() as cap:
        out = sanitize_env(parent, passthrough=["GITHUB_TOKEN"])
    assert out["GITHUB_TOKEN"] == "ghp_xxx"
    matches = [e for e in cap if e.get("event") == "env.passthrough.secret_match"]
    assert len(matches) == 1
    assert matches[0]["var"] == "GITHUB_TOKEN"


def test_passthrough_non_secret_does_not_log_warning() -> None:
    parent = {"DATABASE_URL_TEST": "postgres://x"}
    with structlog.testing.capture_logs() as cap:
        sanitize_env(parent, passthrough=["DATABASE_URL_TEST"])
    matches = [e for e in cap if e.get("event") == "env.passthrough.secret_match"]
    assert len(matches) == 0


def test_passthrough_missing_does_not_log_warning() -> None:
    """Se la var passthrough non è in parent_env, niente warning (niente da loggare)."""
    parent = {"PATH": "/usr/bin"}
    with structlog.testing.capture_logs() as cap:
        sanitize_env(parent, passthrough=["GITHUB_TOKEN"])
    matches = [e for e in cap if e.get("event") == "env.passthrough.secret_match"]
    assert len(matches) == 0
