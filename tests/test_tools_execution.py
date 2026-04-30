"""Test per src/devbox_bridge/tools/execution.py."""

from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path
from typing import Any

import pytest

from devbox_bridge.security.commands import CommandRejectedError
from devbox_bridge.tools.execution import (
    DEFAULT_RUN_COMMAND_TIMEOUT_SECONDS,
    MAX_EXEC_TIMEOUT_SECONDS,
    MAX_OUTPUT_BYTES,
    ExecutableNotFoundError,
    NoCommandConfiguredError,
    TimeoutOutOfRangeError,
    _check_timeout,
    _resolve_executable,
    _truncate_bytes,
    run_build,
    run_command,
    run_lint,
    run_tests,
)
from devbox_bridge.tools.filesystem import WriteNotAllowedError

PYTHON = sys.executable


# --- Helper: sanity skips -----------------------------------------------------


def _require_python() -> None:
    if shutil.which(PYTHON) is None:
        pytest.skip(f"interprete python ({PYTHON}) non trovato")


# --- _truncate_bytes ----------------------------------------------------------


def test_truncate_bytes_shorter_than_max_returns_unchanged() -> None:
    text, was = _truncate_bytes("hello", 100)
    assert text == "hello"
    assert was is False


def test_truncate_bytes_longer_than_max_truncates_with_flag() -> None:
    big = "A" * 200
    text, was = _truncate_bytes(big, 100)
    assert was is True
    assert len(text.encode("utf-8")) <= 100


def test_truncate_bytes_handles_multibyte_chars() -> None:
    """Caratteri multibyte: tronco bytewise non rompe l'output (errors=replace)."""
    # 'è' = 2 byte UTF-8. 100 'è' = 200 byte. max=101 → tronca dentro un char.
    text = "è" * 100
    truncated, was = _truncate_bytes(text, 101)
    assert was is True
    # decoded torna stringa valida (anche se con replacement char alla fine).
    assert isinstance(truncated, str)


# --- _resolve_executable ------------------------------------------------------


def test_resolve_executable_found_returns_absolute_path() -> None:
    _require_python()
    resolved = _resolve_executable("python3")
    assert os.path.isabs(resolved)


def test_resolve_executable_missing_raises() -> None:
    with pytest.raises(ExecutableNotFoundError):
        _resolve_executable("definitely-not-a-real-bin-xyz123")


def test_resolve_executable_relative_path_raises(tmp_path: Path) -> None:
    """Path relativo (./xxx) NON viene risolto rispetto al cwd del subprocess.
    shutil.which usa il cwd del processo Python corrente; comportamento
    documentato in execution._resolve_executable."""
    rel = "./this-relative-path-does-not-exist-anywhere"
    with pytest.raises(ExecutableNotFoundError):
        _resolve_executable(rel)


# --- _check_timeout -----------------------------------------------------------


def test_check_timeout_in_range_ok() -> None:
    assert _check_timeout(60) == 60
    assert _check_timeout(1) == 1
    assert _check_timeout(MAX_EXEC_TIMEOUT_SECONDS) == MAX_EXEC_TIMEOUT_SECONDS


def test_check_timeout_zero_raises() -> None:
    with pytest.raises(TimeoutOutOfRangeError):
        _check_timeout(0)


def test_check_timeout_too_high_raises() -> None:
    with pytest.raises(TimeoutOutOfRangeError):
        _check_timeout(MAX_EXEC_TIMEOUT_SECONDS + 1)


def test_check_timeout_bool_raises() -> None:
    """bool è subclass di int — deve essere rifiutato esplicitamente."""
    with pytest.raises(TimeoutOutOfRangeError):
        _check_timeout(True)  # type: ignore[arg-type]


# --- run_command — gating prerequisiti ---------------------------------------


def test_run_command_write_disabled_raises(config_ro: Any) -> None:
    with pytest.raises(WriteNotAllowedError):
        run_command(config_ro, "myproj", "echo hi")


def test_run_command_timeout_out_of_range_raises(
    config_factory: Any, tmp_project_root: Path
) -> None:
    cfg = config_factory(
        tmp_project_root, write_enabled=True, command_whitelist=["^echo .*$"]
    )
    with pytest.raises(TimeoutOutOfRangeError):
        run_command(cfg, "myproj", "echo hi", timeout=0)
    with pytest.raises(TimeoutOutOfRangeError):
        run_command(cfg, "myproj", "echo hi", timeout=MAX_EXEC_TIMEOUT_SECONDS + 1)


def test_run_command_empty_command_rejected(config_factory: Any, tmp_project_root: Path) -> None:
    cfg = config_factory(
        tmp_project_root, write_enabled=True, command_whitelist=["^echo .*$"]
    )
    with pytest.raises(CommandRejectedError):
        run_command(cfg, "myproj", "")


def test_run_command_not_in_whitelist_rejected(config_factory: Any, tmp_project_root: Path) -> None:
    cfg = config_factory(
        tmp_project_root, write_enabled=True, command_whitelist=["^pytest( .*)?$"]
    )
    with pytest.raises(CommandRejectedError):
        run_command(cfg, "myproj", "echo hi")


def test_run_command_deny_list_blocks_even_in_whitelist(
    config_factory: Any, tmp_project_root: Path
) -> None:
    """rm -rf / passa la fullmatch della whitelist permissiva ma è bloccato dalla deny list."""
    cfg = config_factory(
        tmp_project_root, write_enabled=True, command_whitelist=["^.*$"]
    )
    with pytest.raises(CommandRejectedError):
        run_command(cfg, "myproj", "rm -rf /")


def test_run_command_executable_not_found(config_factory: Any, tmp_project_root: Path) -> None:
    cfg = config_factory(
        tmp_project_root,
        write_enabled=True,
        command_whitelist=["^definitely-not-a-bin.*$"],
    )
    with pytest.raises(ExecutableNotFoundError):
        run_command(cfg, "myproj", "definitely-not-a-bin-xyz123")


# --- run_command — esecuzione effettiva --------------------------------------


def test_run_command_success_exit_zero(config_factory: Any, tmp_project_root: Path) -> None:
    _require_python()
    cfg = config_factory(
        tmp_project_root,
        write_enabled=True,
        command_whitelist=[r"^.+ -c .+$"],
    )
    result = run_command(cfg, "myproj", f"{PYTHON} -c 'print(\"ok\")'")
    assert result["exit_code"] == 0
    assert "ok" in result["stdout"]
    assert result["timed_out"] is False
    assert result["stdout_truncated"] is False
    assert result["stderr_truncated"] is False
    assert result["command"] == f"{PYTHON} -c 'print(\"ok\")'"
    assert result["duration_ms"] >= 0


def test_run_command_nonzero_exit_returns_response_no_exception(
    config_factory: Any, tmp_project_root: Path
) -> None:
    """exit_code != 0 NON è un'eccezione: deve tornare nella response."""
    _require_python()
    cfg = config_factory(
        tmp_project_root, write_enabled=True, command_whitelist=[r"^.+ -c .+$"]
    )
    result = run_command(cfg, "myproj", f"{PYTHON} -c 'import sys; sys.exit(7)'")
    assert result["exit_code"] == 7
    assert result["timed_out"] is False


def test_run_command_stderr_captured(config_factory: Any, tmp_project_root: Path) -> None:
    _require_python()
    cfg = config_factory(
        tmp_project_root, write_enabled=True, command_whitelist=[r"^.+ -c .+$"]
    )
    result = run_command(
        cfg,
        "myproj",
        f"{PYTHON} -c 'import sys; sys.stderr.write(\"boom\")'",
    )
    assert "boom" in result["stderr"]


def test_run_command_timeout_returns_response_no_exception(
    config_factory: Any, tmp_project_root: Path
) -> None:
    """Timeout effettivo: subprocess termina, response normale con timed_out=True.

    Margini larghi: sleep 2 con timeout=1 — niente flake su CI lente.
    """
    _require_python()
    cfg = config_factory(
        tmp_project_root, write_enabled=True, command_whitelist=[r"^.+ -c .+$"]
    )
    result = run_command(
        cfg,
        "myproj",
        f"{PYTHON} -c 'import time; time.sleep(2)'",
        timeout=1,
    )
    assert result["timed_out"] is True
    assert result["exit_code"] == -1


def test_run_command_stdout_over_100kb_truncated(
    config_factory: Any, tmp_project_root: Path
) -> None:
    _require_python()
    cfg = config_factory(
        tmp_project_root, write_enabled=True, command_whitelist=[r"^.+ -c .+$"]
    )
    # 200KB di 'A' su stdout
    result = run_command(
        cfg,
        "myproj",
        f"{PYTHON} -c 'print(\"A\"*200000)'",
    )
    assert result["stdout_truncated"] is True
    assert len(result["stdout"].encode("utf-8")) <= MAX_OUTPUT_BYTES


def test_run_command_stderr_over_100kb_truncated(
    config_factory: Any, tmp_project_root: Path
) -> None:
    _require_python()
    cfg = config_factory(
        tmp_project_root, write_enabled=True, command_whitelist=[r"^.+ -c .+$"]
    )
    result = run_command(
        cfg,
        "myproj",
        f"{PYTHON} -c 'import sys; sys.stderr.write(\"B\"*200000)'",
    )
    assert result["stderr_truncated"] is True
    assert len(result["stderr"].encode("utf-8")) <= MAX_OUTPUT_BYTES


def test_run_command_cwd_is_project_root(
    config_factory: Any, tmp_project_root: Path
) -> None:
    _require_python()
    cfg = config_factory(
        tmp_project_root, write_enabled=True, command_whitelist=[r"^.+ -c .+$"]
    )
    result = run_command(
        cfg,
        "myproj",
        f"{PYTHON} -c 'import os; print(os.getcwd())'",
    )
    expected = str(tmp_project_root.resolve(strict=True))
    assert expected in result["stdout"]


def test_run_command_env_passthrough_propagates(
    config_factory: Any,
    tmp_project_root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("MY_PASSTHROUGH", "hello-world-42")
    cfg = config_factory(
        tmp_project_root,
        write_enabled=True,
        command_whitelist=[r"^.+ -c .+$"],
        env_passthrough=["MY_PASSTHROUGH"],
    )
    result = run_command(
        cfg,
        "myproj",
        f"{PYTHON} -c 'import os; print(os.environ.get(\"MY_PASSTHROUGH\", \"MISSING\"))'",
    )
    assert "hello-world-42" in result["stdout"]


def test_run_command_env_secret_dropped_without_passthrough(
    config_factory: Any,
    tmp_project_root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """API_TOKEN non in env_passthrough → droppato dal sanitizer."""
    monkeypatch.setenv("MY_API_TOKEN", "should-not-leak")
    cfg = config_factory(
        tmp_project_root, write_enabled=True, command_whitelist=[r"^.+ -c .+$"]
    )
    result = run_command(
        cfg,
        "myproj",
        f"{PYTHON} -c 'import os; print(os.environ.get(\"MY_API_TOKEN\", \"MISSING\"))'",
    )
    assert "MISSING" in result["stdout"]
    assert "should-not-leak" not in result["stdout"]


def test_run_command_does_not_use_shell(
    config_factory: Any, tmp_project_root: Path
) -> None:
    """`echo hello && echo world` con shell=False → echo riceve tutto come argv,
    NON viene eseguito un secondo comando dopo `&&`."""
    cfg = config_factory(
        tmp_project_root, write_enabled=True, command_whitelist=[r"^echo .+$"]
    )
    result = run_command(cfg, "myproj", "echo hello && echo world")
    # echo stampa tutti gli argomenti su una sola riga, separati da spazio.
    assert "hello && echo world" in result["stdout"]
    # Se shell=True ci sarebbero due righe distinte. Verifichiamo che NON ci sia
    # una riga isolata "world\n" (cioè senza il prefisso "&& echo ").
    assert "\nworld\n" not in result["stdout"]


# --- run_tests / run_lint / run_build ----------------------------------------


def test_run_tests_no_command_configured_raises(
    config_factory: Any, tmp_project_root: Path
) -> None:
    cfg = config_factory(tmp_project_root, write_enabled=True)
    with pytest.raises(NoCommandConfiguredError):
        run_tests(cfg, "myproj")


def test_run_lint_no_command_configured_raises(
    config_factory: Any, tmp_project_root: Path
) -> None:
    cfg = config_factory(tmp_project_root, write_enabled=True)
    with pytest.raises(NoCommandConfiguredError):
        run_lint(cfg, "myproj")


def test_run_build_no_command_configured_raises(
    config_factory: Any, tmp_project_root: Path
) -> None:
    cfg = config_factory(tmp_project_root, write_enabled=True)
    with pytest.raises(NoCommandConfiguredError):
        run_build(cfg, "myproj")


def test_run_tests_write_disabled_raises(
    config_factory: Any, tmp_project_root: Path
) -> None:
    cfg = config_factory(
        tmp_project_root, write_enabled=False, test_command="echo hi"
    )
    with pytest.raises(WriteNotAllowedError):
        run_tests(cfg, "myproj")


def test_run_tests_deny_list_blocks_configured_command(
    config_factory: Any, tmp_project_root: Path
) -> None:
    """Fail-secure: anche se test_command è nella SoT, deny list la blocca."""
    cfg = config_factory(
        tmp_project_root, write_enabled=True, test_command="rm -rf /"
    )
    with pytest.raises(CommandRejectedError):
        run_tests(cfg, "myproj")


def test_run_tests_bypasses_whitelist(
    config_factory: Any, tmp_project_root: Path
) -> None:
    """test_command non deve passare dalla whitelist regex (è admin-authorized)."""
    _require_python()
    cfg = config_factory(
        tmp_project_root,
        write_enabled=True,
        # NB: command_whitelist VUOTO → run_command rifiuterebbe; run_tests no.
        command_whitelist=[],
        test_command=f"{PYTHON} -c 'print(\"tests ok\")'",
    )
    result = run_tests(cfg, "myproj")
    assert result["exit_code"] == 0
    assert "tests ok" in result["stdout"]


def test_run_tests_nonzero_exit_returns_response(
    config_factory: Any, tmp_project_root: Path
) -> None:
    """test_command che esce ≠ 0 → response normale, NIENTE eccezione.
    È il caso comune dei test rossi."""
    _require_python()
    cfg = config_factory(
        tmp_project_root,
        write_enabled=True,
        test_command=f"{PYTHON} -c 'import sys; sys.exit(1)'",
    )
    result = run_tests(cfg, "myproj")
    assert result["exit_code"] == 1
    assert result["timed_out"] is False


def test_run_lint_smoke(config_factory: Any, tmp_project_root: Path) -> None:
    _require_python()
    cfg = config_factory(
        tmp_project_root,
        write_enabled=True,
        lint_command=f"{PYTHON} -c 'print(\"lint ok\")'",
    )
    result = run_lint(cfg, "myproj")
    assert result["exit_code"] == 0
    assert "lint ok" in result["stdout"]


def test_run_build_smoke(config_factory: Any, tmp_project_root: Path) -> None:
    _require_python()
    cfg = config_factory(
        tmp_project_root,
        write_enabled=True,
        build_command=f"{PYTHON} -c 'print(\"build ok\")'",
    )
    result = run_build(cfg, "myproj")
    assert result["exit_code"] == 0
    assert "build ok" in result["stdout"]


def test_run_tests_relative_path_executable_raises(
    config_factory: Any, tmp_project_root: Path
) -> None:
    """./venv/bin/pytest non viene risolto rispetto al cwd del subprocess.
    Comportamento documentato in execution._resolve_executable."""
    cfg = config_factory(
        tmp_project_root,
        write_enabled=True,
        test_command="./this-relative-path-does-not-exist abc",
    )
    with pytest.raises(ExecutableNotFoundError):
        run_tests(cfg, "myproj")


# --- run_command default timeout ---------------------------------------------


def test_run_command_default_timeout_value() -> None:
    """Costante DEFAULT_RUN_COMMAND_TIMEOUT_SECONDS = 60s."""
    assert DEFAULT_RUN_COMMAND_TIMEOUT_SECONDS == 60
