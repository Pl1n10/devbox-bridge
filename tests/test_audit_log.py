"""Test audit log — audit.py."""

from __future__ import annotations

import gzip
import json
import os
import time
from pathlib import Path

import pytest

from devbox_bridge.audit import (
    ALL_KNOWN_EVENTS,
    AUDITED_AUTH_EVENTS,
    AUDITED_READ_EVENTS,
    AUDITED_REJECTED_EVENTS,
    AUDITED_WRITE_EVENTS,
    AuditEvent,
    AuditLogger,
    sanitize_args,
    should_audit,
    summarize_command_output,
    summarize_content,
)
from devbox_bridge.config import AuditConfig, ServerConfig

# --- helpers ---------------------------------------------------------------


def _make_logger(
    tmp_path: Path,
    *,
    audit_reads: bool = False,
    rotation_size_mb: int = 50,
    retention_days: int = 90,
) -> AuditLogger:
    audit_cfg = AuditConfig(
        log_dir=tmp_path / "audit",
        rotation_size_mb=rotation_size_mb,
        retention_days=retention_days,
        audit_reads=audit_reads,
    )
    server_cfg = ServerConfig(log_dir=tmp_path / "server-logs")
    return AuditLogger(audit_cfg, server_cfg)


def _read_lines(log_path: Path) -> list[dict]:
    if not log_path.exists():
        return []
    return [json.loads(line) for line in log_path.read_text(encoding="utf-8").splitlines()]


# --- schema ----------------------------------------------------------------


def test_audit_event_schema_required_fields() -> None:
    ev = AuditEvent(
        timestamp="2026-04-28T10:00:00.000Z",
        event="tool.write_file",
        outcome="success",
    )
    d = ev.model_dump()
    for field in (
        "timestamp",
        "event",
        "outcome",
        "token_id",
        "client_ip",
        "project",
        "tool",
        "args_summary",
        "duration_ms",
        "error_class",
        "error_message",
    ):
        assert field in d


def test_audit_event_outcome_validated() -> None:
    with pytest.raises(ValueError):
        AuditEvent(timestamp="x", event="e", outcome="banana")


def test_audit_event_extra_field_rejected() -> None:
    with pytest.raises(ValueError):
        AuditEvent(  # type: ignore[call-arg]
            timestamp="x",
            event="e",
            outcome="success",
            unknown_field="oops",
        )


# --- should_audit ----------------------------------------------------------


def test_should_audit_auth_always() -> None:
    assert should_audit("auth.failed", audit_reads=False) is True
    assert should_audit("auth.rate_limited", audit_reads=False) is True


def test_should_audit_rejected_always() -> None:
    assert should_audit("command.rejected", audit_reads=False) is True
    assert should_audit("path.rejected", audit_reads=False) is True


def test_should_audit_write_always() -> None:
    for ev in AUDITED_WRITE_EVENTS:
        assert should_audit(ev, audit_reads=False) is True


def test_should_audit_read_only_when_enabled() -> None:
    for ev in AUDITED_READ_EVENTS:
        assert should_audit(ev, audit_reads=False) is False
        assert should_audit(ev, audit_reads=True) is True


def test_should_audit_unknown_event_logs_by_default() -> None:
    """Eventi non noti: log di default (più sicuro)."""
    assert should_audit("tool.weird_new_thing", audit_reads=False) is True


def test_audited_events_constants_exhaustive() -> None:
    """Sanity: ogni tool write declared nel brief deve essere in AUDITED_WRITE_EVENTS."""
    expected_writes = {
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
    assert expected_writes <= AUDITED_WRITE_EVENTS


def test_known_events_partition_disjoint() -> None:
    """I quattro set non si sovrappongono."""
    sets = [AUDITED_AUTH_EVENTS, AUDITED_REJECTED_EVENTS, AUDITED_WRITE_EVENTS, AUDITED_READ_EVENTS]
    union_size = sum(len(s) for s in sets)
    assert len(ALL_KNOWN_EVENTS) == union_size


# --- sanitize_args ---------------------------------------------------------


def test_sanitize_args_redacts_token_keys() -> None:
    out = sanitize_args({"token": "secret-value", "other": "ok"})
    assert out["token"] == "<redacted>"
    assert out["other"] == "ok"


def test_sanitize_args_case_insensitive_key_match() -> None:
    out = sanitize_args({"AuthToken": "x", "API_KEY": "y", "MyPassword": "z"})
    assert out["AuthToken"] == "<redacted>"
    assert out["API_KEY"] == "<redacted>"
    assert out["MyPassword"] == "<redacted>"


def test_sanitize_args_substring_key_match() -> None:
    out = sanitize_args({"github_access_token": "ghp_xxx"})
    assert out["github_access_token"] == "<redacted>"


def test_sanitize_args_redacts_path_with_env_segment() -> None:
    out = sanitize_args({"path": "/home/x/.env"})
    assert out["path"] == "<redacted-path>"


def test_sanitize_args_redacts_path_with_secrets_segment() -> None:
    out = sanitize_args({"path": "/etc/secrets/db.yaml"})
    assert out["path"] == "<redacted-path>"


def test_sanitize_args_redacts_ssh_path() -> None:
    out = sanitize_args({"path": "/home/x/.ssh/id_rsa"})
    assert out["path"] == "<redacted-path>"


def test_sanitize_args_keeps_normal_path() -> None:
    out = sanitize_args({"path": "/home/x/projects/foo/bar.py"})
    assert out["path"] == "/home/x/projects/foo/bar.py"


def test_sanitize_args_recursive_dict() -> None:
    out = sanitize_args({"outer": {"token": "x", "ok": "y"}})
    assert out["outer"]["token"] == "<redacted>"
    assert out["outer"]["ok"] == "y"


def test_sanitize_args_recursive_list() -> None:
    out = sanitize_args({"paths": ["/home/x/.env", "/home/x/normal.py"]})
    assert out["paths"][0] == "<redacted-path>"
    assert out["paths"][1] == "/home/x/normal.py"


def test_sanitize_args_does_not_redact_non_path_string_with_dot() -> None:
    """'.env' come segmento di path → redact. '.env' come parte di altro testo → no."""
    out = sanitize_args({"description": "uses .env file"})
    assert out["description"] == "uses .env file"


# --- summarize helpers -----------------------------------------------------


def test_summarize_content_str() -> None:
    s = summarize_content("hello world")
    assert s["bytes"] == 11
    assert len(s["content_sha8"]) == 8


def test_summarize_content_bytes() -> None:
    s = summarize_content(b"\x00\x01\x02")
    assert s["bytes"] == 3


def test_summarize_command_output_short() -> None:
    s = summarize_command_output("hi")
    assert s["full"] == "hi"
    assert s["truncated"] is False
    assert "head" not in s


def test_summarize_command_output_truncated() -> None:
    s = summarize_command_output("a" * 5000, head_chars=100, tail_chars=100)
    assert s["truncated"] is True
    assert len(s["head"]) == 100
    assert len(s["tail"]) == 100
    assert s["total_bytes"] == 5000
    assert "full" not in s


# --- AuditLogger end-to-end ------------------------------------------------


def test_logger_writes_to_file(tmp_path: Path) -> None:
    log = _make_logger(tmp_path)
    log.log(
        "tool.write_file",
        "success",
        token_id="abcd1234",
        project="myproj",
        tool="write_file",
        args={"path": "src/foo.py", "bytes": 42, "content_sha8": "deadbeef"},
        duration_ms=12.3,
    )
    lines = _read_lines(log.current_log_path)
    assert len(lines) == 1
    rec = lines[0]
    assert rec["event"] == "tool.write_file"
    assert rec["outcome"] == "success"
    assert rec["token_id"] == "abcd1234"
    assert rec["project"] == "myproj"
    assert rec["args_summary"]["path"] == "src/foo.py"
    assert rec["duration_ms"] == 12.3


def test_logger_no_token_plain_in_output(tmp_path: Path) -> None:
    """Sanity guard: il token plain non deve mai apparire nel log."""
    plain_token = "s3cr3t-plain-token-abc"
    log = _make_logger(tmp_path)
    log.log(
        "tool.write_file",
        "success",
        token_id="abcd1234",
        args={"some_token": plain_token, "auth_token_value": plain_token},
    )
    text = log.current_log_path.read_text(encoding="utf-8")
    assert plain_token not in text


def test_logger_redacts_secret_path_segments(tmp_path: Path) -> None:
    log = _make_logger(tmp_path)
    log.log(
        "tool.read_file",
        "success",
        args={"path": "/home/x/.ssh/id_rsa"},
    )
    # Read non auditato di default → niente file
    assert not log.current_log_path.exists()

    log2 = _make_logger(tmp_path / "x", audit_reads=True)
    log2.log("tool.read_file", "success", args={"path": "/home/x/.ssh/id_rsa"})
    rec = _read_lines(log2.current_log_path)[0]
    assert rec["args_summary"]["path"] == "<redacted-path>"


def test_logger_skips_read_events_by_default(tmp_path: Path) -> None:
    log = _make_logger(tmp_path, audit_reads=False)
    log.log("tool.read_file", "success", args={"path": "src/foo.py"})
    log.log("tool.list_directory", "success", args={"path": "src"})
    log.log("tool.git_status", "success", project="x")
    assert not log.current_log_path.exists()


def test_logger_logs_read_events_when_enabled(tmp_path: Path) -> None:
    log = _make_logger(tmp_path, audit_reads=True)
    log.log("tool.read_file", "success", args={"path": "src/foo.py"})
    lines = _read_lines(log.current_log_path)
    assert len(lines) == 1
    assert lines[0]["event"] == "tool.read_file"


def test_logger_logs_auth_failed(tmp_path: Path) -> None:
    log = _make_logger(tmp_path)
    log.log("auth.failed", "denied", token_id="(none)", client_ip="100.64.1.2")
    lines = _read_lines(log.current_log_path)
    assert len(lines) == 1
    assert lines[0]["event"] == "auth.failed"
    assert lines[0]["outcome"] == "denied"


def test_logger_logs_rejected_command(tmp_path: Path) -> None:
    log = _make_logger(tmp_path)
    log.log(
        "command.rejected",
        "denied",
        project="myproj",
        args={"command": "rm -rf /"},
        error_class="CommandRejectedError",
        error_message="rm -r su path di sistema bloccato",
    )
    lines = _read_lines(log.current_log_path)
    assert lines[0]["error_class"] == "CommandRejectedError"


def test_logger_jsonl_format_valid(tmp_path: Path) -> None:
    """Ogni linea deve essere JSON parsabile indipendentemente."""
    log = _make_logger(tmp_path)
    for i in range(5):
        log.log("tool.write_file", "success", args={"i": i})
    text = log.current_log_path.read_text(encoding="utf-8")
    for line in text.splitlines():
        json.loads(line)  # solleva se non valido


def test_logger_timestamp_iso_with_z(tmp_path: Path) -> None:
    log = _make_logger(tmp_path)
    log.log("tool.write_file", "success")
    rec = _read_lines(log.current_log_path)[0]
    assert rec["timestamp"].endswith("Z")
    # parsable come iso8601 con "Z" sostituito da +00:00
    from datetime import datetime

    datetime.fromisoformat(rec["timestamp"].replace("Z", "+00:00"))


# --- rotazione -------------------------------------------------------------


def test_rotation_triggers_at_size_limit(tmp_path: Path) -> None:
    # 1MB rotation → rotazione dopo ~1MB di payload
    log = _make_logger(tmp_path, rotation_size_mb=1)
    big_arg = {"x": "A" * 2000}
    for _ in range(700):  # ~700 linee × ~2KB = ~1.4MB
        log.log("tool.write_file", "success", args=big_arg)

    # Almeno un file gz nella log_dir
    gz_files = list(log.log_dir.glob("audit-*.log.gz"))
    assert len(gz_files) >= 1, f"nessun file ruotato in {log.log_dir}"

    # Il gz deve contenere JSON parsabile
    with gzip.open(gz_files[0], "rt", encoding="utf-8") as f:
        for line in f:
            json.loads(line)


def test_rotation_atomic_no_event_lost(tmp_path: Path) -> None:
    """Ogni evento scritto deve finire in current OR in un .gz, mai perso."""
    log = _make_logger(tmp_path, rotation_size_mb=1)
    big_arg = {"x": "B" * 2000}
    n_events = 700
    for i in range(n_events):
        log.log("tool.write_file", "success", args={"i": i, **big_arg})

    # Conta linee in current + tutti i .gz
    total = 0
    if log.current_log_path.exists():
        total += len(_read_lines(log.current_log_path))
    for gz in log.log_dir.glob("audit-*.log.gz"):
        with gzip.open(gz, "rt", encoding="utf-8") as f:
            total += sum(1 for _ in f)

    assert total == n_events, f"persi eventi: scritti {n_events}, trovati {total}"


# --- retention -------------------------------------------------------------


def test_retention_deletes_old_gz(tmp_path: Path) -> None:
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()

    # Crea un .gz "vecchio" con mtime di 100 giorni fa
    old = audit_dir / "audit-20260101-000000.log.gz"
    old.write_bytes(b"")
    old_mtime = time.time() - (100 * 86400)
    os.utime(old, (old_mtime, old_mtime))

    # E uno recente
    recent = audit_dir / "audit-20260420-000000.log.gz"
    recent.write_bytes(b"")
    # mtime di default = ora

    # Costruisce logger con retention_days=90 → cleanup all'init
    audit_cfg = AuditConfig(
        log_dir=audit_dir,
        retention_days=90,
    )
    server_cfg = ServerConfig(log_dir=tmp_path / "server-logs")
    AuditLogger(audit_cfg, server_cfg)

    assert not old.exists(), "file vecchio non eliminato"
    assert recent.exists(), "file recente eliminato per errore"


# --- defaults --------------------------------------------------------------


def test_audit_config_defaults() -> None:
    cfg = AuditConfig()
    assert cfg.log_dir is None
    assert cfg.rotation_size_mb == 50
    assert cfg.retention_days == 90
    assert cfg.audit_reads is False


def test_default_log_dir_falls_back_to_server(tmp_path: Path) -> None:
    audit_cfg = AuditConfig()  # log_dir=None
    server_cfg = ServerConfig(log_dir=tmp_path / "server-logs")
    log = AuditLogger(audit_cfg, server_cfg)
    assert log.log_dir == tmp_path / "server-logs" / "audit"
    assert log.log_dir.exists()
