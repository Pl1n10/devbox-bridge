"""Audit logger strutturato per azioni write/exec/auth-fail.

Schema fisso JSON (un evento per linea), rotazione per size, gzip dei file
ruotati, retention configurabile, sanitizzazione di campi sensibili.

Sanitizzazione (defense in depth — è la "seconda riga" dopo i tool):
  - Token plain mai loggato (usa token_log_id da auth.py).
  - Chiavi che contengono "token", "password", "secret", "key", "api_key",
    "passwd" → valore sostituito con '<redacted>' (case-insensitive,
    substring match).
  - Path che contengono segmenti '.env', 'secrets', 'credentials', '.aws',
    '.ssh', '.gnupg' → '<redacted-path>'.
  - Sanitizzazione ricorsiva su dict/list annidati.

Eventi:
  - Sempre auditati: auth.failed, auth.rate_limited, command.rejected,
    path.rejected, e tutti i tool write/exec.
  - Read tools (read_file, list_directory, ecc.): auditati SOLO se
    audit.audit_reads=true in config (per default off → meno rumore).
"""

from __future__ import annotations

import gzip
import hashlib
import json
import re
import shutil
import threading
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from devbox_bridge.config import AuditConfig, ServerConfig

# --- Eventi auditati -------------------------------------------------------

AUDITED_AUTH_EVENTS: frozenset[str] = frozenset(
    {
        "auth.failed",
        "auth.rate_limited",
    }
)

AUDITED_REJECTED_EVENTS: frozenset[str] = frozenset(
    {
        "command.rejected",
        "path.rejected",
    }
)

AUDITED_WRITE_EVENTS: frozenset[str] = frozenset(
    {
        "tool.write_file",
        "tool.apply_patch",
        "tool.git_commit",
        "tool.git_push",
        "tool.git_create_branch",
        "tool.run_command",
        "tool.run_tests",
        "tool.run_lint",
        "tool.run_build",
    }
)

AUDITED_READ_EVENTS: frozenset[str] = frozenset(
    {
        "tool.read_file",
        "tool.list_projects",
        "tool.list_directory",
        "tool.search_files",
        "tool.git_status",
        "tool.git_diff",
        "tool.git_log",
        "tool.git_branch_current",
        "tool.tail_log",
        "tool.list_systemd_services",
        "tool.get_system_info",
    }
)

ALL_KNOWN_EVENTS: frozenset[str] = (
    AUDITED_AUTH_EVENTS
    | AUDITED_REJECTED_EVENTS
    | AUDITED_WRITE_EVENTS
    | AUDITED_READ_EVENTS
)


# --- Sanitizzazione --------------------------------------------------------

_REDACT_KEY_SUBSTRINGS: frozenset[str] = frozenset(
    {
        "token",
        "password",
        "passwd",
        "secret",
        "api_key",
        "apikey",
        "private_key",
    }
)

_REDACT_PATH_SEGMENTS: frozenset[str] = frozenset(
    {
        ".env",
        "secrets",
        "credentials",
        ".aws",
        ".ssh",
        ".gnupg",
        ".kube",
        ".docker",
    }
)

_REDACTED = "<redacted>"
_REDACTED_PATH = "<redacted-path>"
_PATH_HEURISTIC = re.compile(r"^(/|\.{0,2}/|~/|[a-zA-Z]:[\\/])")


def _is_redact_key(key: str) -> bool:
    klow = key.lower()
    return any(sub in klow for sub in _REDACT_KEY_SUBSTRINGS)


def _looks_like_path(value: str) -> bool:
    return bool(_PATH_HEURISTIC.match(value))


def _path_has_secret_segment(value: str) -> bool:
    if not _looks_like_path(value):
        return False
    parts = Path(value).parts
    return any(seg in _REDACT_PATH_SEGMENTS for seg in parts)


def _sanitize_value(value: Any) -> Any:
    if isinstance(value, dict):
        return sanitize_args(value)
    if isinstance(value, list):
        return [_sanitize_value(v) for v in value]
    if isinstance(value, tuple):
        return tuple(_sanitize_value(v) for v in value)
    if isinstance(value, str) and _path_has_secret_segment(value):
        return _REDACTED_PATH
    return value


def sanitize_args(args: Mapping[str, Any]) -> dict[str, Any]:
    """Pass ricorsivo: redatta chiavi sensibili e path che contengono secret-segments."""
    out: dict[str, Any] = {}
    for k, v in args.items():
        if _is_redact_key(k):
            out[k] = _REDACTED
            continue
        out[k] = _sanitize_value(v)
    return out


def summarize_content(content: bytes | str, encoding: str = "utf-8") -> dict[str, Any]:
    """Helper per i tool: riassume il payload di read_file/write_file senza
    metterlo in chiaro nell'audit log."""
    if isinstance(content, str):
        content_bytes = content.encode(encoding, errors="replace")
    else:
        content_bytes = content
    return {
        "bytes": len(content_bytes),
        "content_sha8": hashlib.sha256(content_bytes).hexdigest()[:8],
    }


def summarize_command_output(
    output: str,
    head_chars: int = 500,
    tail_chars: int = 500,
) -> dict[str, Any]:
    """Helper per run_command/run_tests: head + tail + hash totale + bytes."""
    encoded = output.encode("utf-8", errors="replace")
    summary: dict[str, Any] = {
        "total_bytes": len(encoded),
        "total_sha8": hashlib.sha256(encoded).hexdigest()[:8],
    }
    if len(output) <= head_chars + tail_chars:
        summary["full"] = output
        summary["truncated"] = False
    else:
        summary["head"] = output[:head_chars]
        summary["tail"] = output[-tail_chars:]
        summary["truncated"] = True
    return summary


# --- Schema evento ---------------------------------------------------------


class AuditEvent(BaseModel):
    """Schema fisso per ogni linea dell'audit log."""

    model_config = ConfigDict(extra="forbid")

    timestamp: str  # ISO8601 UTC con suffisso Z
    event: str
    outcome: str = Field(pattern=r"^(success|denied|error)$")
    token_id: str | None = None
    client_ip: str | None = None
    project: str | None = None
    tool: str | None = None
    args_summary: dict[str, Any] | None = None
    duration_ms: float | None = None
    error_class: str | None = None
    error_message: str | None = None


def _utc_now_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.") + (
        f"{datetime.now(UTC).microsecond // 1000:03d}Z"
    )


# --- Logger ----------------------------------------------------------------


def should_audit(event: str, *, audit_reads: bool) -> bool:
    """True se l'evento va loggato data la policy corrente."""
    if event in AUDITED_AUTH_EVENTS:
        return True
    if event in AUDITED_REJECTED_EVENTS:
        return True
    if event in AUDITED_WRITE_EVENTS:
        return True
    if event in AUDITED_READ_EVENTS:
        return audit_reads
    # Eventi non noti: log di default (più sicuro). I test lo coprono.
    return True


class AuditLogger:
    """Logger thread-safe con rotazione per size e gzip post-rotazione.

    Atomic-rename: durante la rotazione il file corrente viene rinominato
    (rename è atomico su POSIX su stesso fs), poi gzippato, poi un nuovo
    file viene aperto. Sotto Lock, nessuna scrittura va persa.
    """

    def __init__(
        self,
        audit_config: AuditConfig,
        server_config: ServerConfig,
    ) -> None:
        self._audit_reads = audit_config.audit_reads
        self._rotation_size = audit_config.rotation_size_mb * 1024 * 1024
        self._retention_days = audit_config.retention_days

        log_dir = audit_config.log_dir or (server_config.log_dir / "audit")
        log_dir.mkdir(parents=True, exist_ok=True)
        self._log_dir = log_dir
        self._current_path = log_dir / "audit.log"

        self._lock = threading.Lock()
        self._cleanup_old_files()

    @property
    def log_dir(self) -> Path:
        return self._log_dir

    @property
    def current_log_path(self) -> Path:
        return self._current_path

    def log(
        self,
        event: str,
        outcome: str,
        *,
        token_id: str | None = None,
        client_ip: str | None = None,
        project: str | None = None,
        tool: str | None = None,
        args: Mapping[str, Any] | None = None,
        duration_ms: float | None = None,
        error_class: str | None = None,
        error_message: str | None = None,
    ) -> None:
        """Logga un evento di audit. Il `tool` può essere None per eventi
        non-tool (auth.failed, command.rejected, ...)."""
        if not should_audit(event, audit_reads=self._audit_reads):
            return

        sanitized = sanitize_args(dict(args)) if args else None
        record = AuditEvent(
            timestamp=_utc_now_iso(),
            event=event,
            outcome=outcome,
            token_id=token_id,
            client_ip=client_ip,
            project=project,
            tool=tool,
            args_summary=sanitized,
            duration_ms=duration_ms,
            error_class=error_class,
            error_message=error_message,
        )
        line = json.dumps(record.model_dump(), ensure_ascii=False, sort_keys=True)

        with self._lock:
            self._maybe_rotate_locked()
            with self._current_path.open("a", encoding="utf-8") as f:
                f.write(line + "\n")

    def _maybe_rotate_locked(self) -> None:
        if not self._current_path.exists():
            return
        try:
            size = self._current_path.stat().st_size
        except FileNotFoundError:
            return
        if size < self._rotation_size:
            return

        ts = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
        rotated_plain = self._log_dir / f"audit-{ts}.log"
        # Atomic rename (posix, same fs).
        self._current_path.rename(rotated_plain)
        # Gzip e rimuovi il plain.
        gz_path = rotated_plain.with_suffix(rotated_plain.suffix + ".gz")
        with rotated_plain.open("rb") as sf, gzip.open(gz_path, "wb") as df:
            shutil.copyfileobj(sf, df)
        rotated_plain.unlink()
        self._cleanup_old_files()

    def _cleanup_old_files(self) -> None:
        cutoff = datetime.now(UTC) - timedelta(days=self._retention_days)
        cutoff_ts = cutoff.timestamp()
        for f in self._log_dir.glob("audit-*.log.gz"):
            try:
                if f.stat().st_mtime < cutoff_ts:
                    f.unlink()
            except FileNotFoundError:
                continue
