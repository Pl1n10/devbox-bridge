"""Tool MCP — execution.

Tool implementati nello step 9.

Write/exec (richiedono project.write_enabled, audit obbligatorio nel server):
  - run_tests   → esegue proj.test_command
  - run_lint    → esegue proj.lint_command
  - run_build   → esegue proj.build_command
  - run_command → esegue comando arbitrario (deny list + whitelist regex)

Differenze chiave dai tool git:
  - exit_code != 0 e timeout NON sollevano eccezione: sono outcome legittimi
    (test che falliscono, build lenta). La response normale ha exit_code,
    timed_out, stdout/stderr troncati. L'audit nel server registra
    outcome="success" con outcome_detail in {completed, nonzero_exit,
    timed_out}.
  - Sollevano: WriteNotAllowedError, NoCommandConfiguredError,
    ExecutableNotFoundError, CommandRejectedError, TimeoutOutOfRangeError.

Validazione comando:
  - run_command       → security.commands.check_command (deny + whitelist).
  - run_tests/lint/build → security.commands.check_deny_list (solo deny).
    Razionale: i 3 comandi configurati sono amministrativamente autorizzati
    (sono in config.yaml, SoT del progetto), ma la deny list resta come
    fail-secure contro errori di config tipo `pytest && rm -rf /etc` in
    test_command.

Invarianti:
  - subprocess.run con lista args, mai shell=True.
  - cwd forzato a project root.
  - env sanitizzato via security.env.sanitize_env() (no LD_PRELOAD; secret
    droppati per default; env_passthrough rispettato).
  - stdin=DEVNULL (no prompt interattivo).
  - timeout obbligatorio in [1, MAX_EXEC_TIMEOUT_SECONDS].
  - stdout/stderr troncati a MAX_OUTPUT_BYTES con flag.

Mapping eccezioni → server outcome:
  WriteNotAllowedError              → "denied"
  NoCommandConfiguredError          → "error"
  ExecutableNotFoundError           → "error"
  CommandRejectedError              → "denied" (event "command.rejected")
  TimeoutOutOfRangeError            → "error"
"""

from __future__ import annotations

import shlex
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any

from devbox_bridge.config import AppConfig, ProjectConfig
from devbox_bridge.security.commands import (
    CommandRejectedError,
    check_command,
    check_deny_list,
)
from devbox_bridge.security.env import get_current_env, sanitize_env
from devbox_bridge.tools.filesystem import WriteNotAllowedError

# --- Costanti -----------------------------------------------------------------

# Cap assoluto sul timeout, anche per run_command user-provided. Il brief
# fissa 600s come massimo: un subprocess non deve poter occupare il bridge
# >10 minuti. Cambia solo se il brief cambia.
MAX_EXEC_TIMEOUT_SECONDS: int = 600

# Default per run_command (user-provided runtime). Stretto perché il client
# può alzarlo fino a MAX_EXEC_TIMEOUT_SECONDS quando serve davvero.
DEFAULT_RUN_COMMAND_TIMEOUT_SECONDS: int = 60

# Default per i comandi configurati (test/lint/build). Più alto perché
# pytest+postgres su sidebiz-agent o build Go di Nekontrol non rientrano
# nei 60s. Hardcoded e non per-progetto: YAGNI finché un progetto reale
# non eccede i 5 minuti — allora si aggiunge ProjectConfig.test_timeout_seconds.
DEFAULT_CONFIGURED_TIMEOUT_SECONDS: int = 300

# Output truncation per la response client (separato per stdout e stderr).
# L'audit usa audit.summarize_command_output() (head 500 + tail 500 + sha8)
# che è meno verboso e adatto a un log JSON.
MAX_OUTPUT_BYTES: int = 100 * 1024


# --- Eccezioni ----------------------------------------------------------------


class ExecutableNotFoundError(RuntimeError):
    """argv[0] non trovato nel PATH (o non eseguibile)."""


class NoCommandConfiguredError(LookupError):
    """test_command / lint_command / build_command è None per il progetto."""


class TimeoutOutOfRangeError(ValueError):
    """timeout fuori dall'intervallo [1, MAX_EXEC_TIMEOUT_SECONDS]."""


# --- Helper privati -----------------------------------------------------------


def _project(cfg: AppConfig, project: str) -> ProjectConfig:
    return cfg.project(project)


def _project_root(proj: ProjectConfig) -> Path:
    return proj.path.resolve(strict=True)


def _build_env(proj: ProjectConfig) -> dict[str, str]:
    return sanitize_env(get_current_env(), passthrough=proj.env_passthrough)


def _ensure_writable(proj: ProjectConfig, project_name: str) -> None:
    if not proj.write_enabled:
        raise WriteNotAllowedError(
            f"project '{project_name}' ha write_enabled=False"
        )


def _check_timeout(timeout: int) -> int:
    # bool è subclass di int → escludo esplicitamente.
    if not isinstance(timeout, int) or isinstance(timeout, bool):
        raise TimeoutOutOfRangeError(
            f"timeout deve essere int, ho {type(timeout).__name__}"
        )
    if timeout < 1 or timeout > MAX_EXEC_TIMEOUT_SECONDS:
        raise TimeoutOutOfRangeError(
            f"timeout {timeout}s fuori da [1, {MAX_EXEC_TIMEOUT_SECONDS}]"
        )
    return timeout


def _truncate_bytes(text: str, max_bytes: int) -> tuple[str, bool]:
    """Tronca text a max_bytes UTF-8. Ritorna (text_troncato, was_truncated)."""
    encoded = text.encode("utf-8", errors="replace")
    if len(encoded) <= max_bytes:
        return text, False
    truncated = encoded[:max_bytes].decode("utf-8", errors="replace")
    return truncated, True


def _resolve_executable(argv0: str) -> str:
    """Risolve argv0 a path assoluto via shutil.which.

    Solleva ExecutableNotFoundError se non trovato.

    Note:
      - argv0 path assoluto: shutil.which lo restituisce se esiste ed è
        eseguibile.
      - argv0 path relativo tipo `./venv/bin/pytest`: shutil.which NON
        risolve rispetto al cwd custom del subprocess (vede il cwd del
        bridge stesso) → tipicamente ritorna None → solleva.
        Comportamento intenzionale: configurare test_command con nomi
        binari nel PATH o path assoluti.
    """
    resolved = shutil.which(argv0)
    if resolved is None:
        raise ExecutableNotFoundError(
            f"executable '{argv0}' non trovato nel PATH"
        )
    return resolved


def _decode_stream(value: bytes | str | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def _run_subprocess(
    proj: ProjectConfig,
    command: str,
    timeout: int,
) -> dict[str, Any]:
    """Esegue command con cwd=project_root, env sanitizzato, stdin=DEVNULL.

    NON solleva su exit_code != 0 o timeout: sono outcome legittimi.
    Solleva ExecutableNotFoundError se argv[0] non è nel PATH.

    Pre-condizioni:
      - command è già stato validato (deny list e/o whitelist).
      - timeout è già stato validato in [1, MAX_EXEC_TIMEOUT_SECONDS].
    """
    argv = shlex.split(command, posix=True)
    if not argv:
        # Già coperto da check_deny_list (comando vuoto); difesa in profondità.
        raise CommandRejectedError("comando vuoto")
    resolved = _resolve_executable(argv[0])
    full_argv = [resolved, *argv[1:]]

    started = time.monotonic()
    timed_out = False
    try:
        proc = subprocess.run(  # noqa: S603 — argv0 da shutil.which, args lista
            full_argv,
            cwd=str(_project_root(proj)),
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            env=_build_env(proj),
        )
        exit_code = proc.returncode
        stdout_raw = proc.stdout
        stderr_raw = proc.stderr
    except subprocess.TimeoutExpired as e:
        timed_out = True
        exit_code = -1
        stdout_raw = _decode_stream(e.stdout)
        stderr_raw = _decode_stream(e.stderr)
    duration_ms = (time.monotonic() - started) * 1000

    stdout, stdout_truncated = _truncate_bytes(stdout_raw, MAX_OUTPUT_BYTES)
    stderr, stderr_truncated = _truncate_bytes(stderr_raw, MAX_OUTPUT_BYTES)

    return {
        "command": command,
        "exit_code": exit_code,
        "duration_ms": round(duration_ms, 1),
        "stdout": stdout,
        "stderr": stderr,
        "stdout_truncated": stdout_truncated,
        "stderr_truncated": stderr_truncated,
        "timed_out": timed_out,
    }


def _run_configured(
    cfg: AppConfig,
    project: str,
    field_name: str,
    field_value: str | None,
) -> dict[str, Any]:
    proj = _project(cfg, project)
    _ensure_writable(proj, project)
    if field_value is None:
        raise NoCommandConfiguredError(
            f"project '{project}' non ha {field_name} configurato"
        )
    check_deny_list(field_value)
    return _run_subprocess(proj, field_value, DEFAULT_CONFIGURED_TIMEOUT_SECONDS)


# --- Tool pubblici ------------------------------------------------------------


def run_command(
    cfg: AppConfig,
    project: str,
    command: str,
    timeout: int = DEFAULT_RUN_COMMAND_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    """Esegue un comando arbitrario nel cwd del progetto.

    Validazione (in ordine):
      1. project.write_enabled = True (else WriteNotAllowedError).
      2. timeout in [1, MAX_EXEC_TIMEOUT_SECONDS] (else TimeoutOutOfRangeError).
      3. command passa deny list + whitelist regex re.fullmatch
         (else CommandRejectedError).
      4. argv[0] risolvibile via shutil.which (else ExecutableNotFoundError).
    """
    proj = _project(cfg, project)
    _ensure_writable(proj, project)
    _check_timeout(timeout)
    check_command(command, proj.command_whitelist)
    return _run_subprocess(proj, command, timeout)


def run_tests(cfg: AppConfig, project: str) -> dict[str, Any]:
    """Esegue project.test_command con timeout DEFAULT_CONFIGURED_TIMEOUT_SECONDS.

    Validazione: write_enabled, test_command non None, deny list (no whitelist).
    """
    proj = _project(cfg, project)
    return _run_configured(cfg, project, "test_command", proj.test_command)


def run_lint(cfg: AppConfig, project: str) -> dict[str, Any]:
    """Esegue project.lint_command con timeout DEFAULT_CONFIGURED_TIMEOUT_SECONDS.

    Validazione: write_enabled, lint_command non None, deny list (no whitelist).
    """
    proj = _project(cfg, project)
    return _run_configured(cfg, project, "lint_command", proj.lint_command)


def run_build(cfg: AppConfig, project: str) -> dict[str, Any]:
    """Esegue project.build_command con timeout DEFAULT_CONFIGURED_TIMEOUT_SECONDS.

    Validazione: write_enabled, build_command non None, deny list (no whitelist).
    """
    proj = _project(cfg, project)
    return _run_configured(cfg, project, "build_command", proj.build_command)
