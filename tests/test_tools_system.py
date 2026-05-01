"""Test per src/devbox_bridge/tools/system.py."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

from devbox_bridge.config import (
    AppConfig,
    AuditConfig,
    AuthConfig,
    ServerConfig,
    SystemConfig,
)
from devbox_bridge.tools.system import (
    DEFAULT_LOG_LINES,
    MAX_LOG_LINES,
    MAX_LOG_OUTPUT_BYTES,
    FilterPatternError,
    JournalctlNotAvailableError,
    JournalctlUnitNotAllowedError,
    LinesOutOfRangeError,
    LogPathNotAllowedError,
    LogPathNotFoundError,
    SystemctlNotAvailableError,
    TailNotAvailableError,
    _check_lines,
    _truncate_bytes,
    _which_or_raise,
    get_system_info,
    list_systemd_services,
    read_journalctl,
    tail_log,
)

# --- Fixture di comodo -------------------------------------------------------


def _system_cfg(
    tmp_path: Path,
    tmp_token_file: Path,
    *,
    log_paths: list[Path] | None = None,
    units: list[str] | None = None,
    filter_default: str = "devbox-",
) -> AppConfig:
    """Costruisce un AppConfig con SystemConfig parametrizzata.
    log_paths=None → default permissivo SystemConfig (non passa il field).
    log_paths=[] → fail-secure (lista esplicitamente vuota).
    """
    sys_kwargs: dict[str, Any] = {"systemd_filter_default": filter_default}
    if log_paths is not None:
        sys_kwargs["log_paths_whitelist"] = log_paths
    if units is not None:
        sys_kwargs["systemd_unit_whitelist"] = units
    return AppConfig(
        server=ServerConfig(log_dir=tmp_path / "logs"),
        auth=AuthConfig(token_hash_file=tmp_token_file),
        audit=AuditConfig(log_dir=tmp_path / "logs" / "audit"),
        system=SystemConfig(**sys_kwargs),
    )


# --- _check_lines / _truncate_bytes / _which_or_raise -----------------------


def test_check_lines_valid() -> None:
    assert _check_lines(1) == 1
    assert _check_lines(100) == 100
    assert _check_lines(MAX_LOG_LINES) == MAX_LOG_LINES


def test_check_lines_zero_raises() -> None:
    with pytest.raises(LinesOutOfRangeError):
        _check_lines(0)


def test_check_lines_too_high_raises() -> None:
    with pytest.raises(LinesOutOfRangeError):
        _check_lines(MAX_LOG_LINES + 1)


def test_check_lines_bool_raises() -> None:
    with pytest.raises(LinesOutOfRangeError):
        _check_lines(True)  # type: ignore[arg-type]


def test_truncate_bytes_short_returns_unchanged() -> None:
    text, was = _truncate_bytes("hello", 100)
    assert text == "hello"
    assert was is False


def test_truncate_bytes_long_truncates() -> None:
    big = "A" * 200
    text, was = _truncate_bytes(big, 100)
    assert was is True
    assert len(text.encode("utf-8")) <= 100


def test_which_or_raise_found_returns_path() -> None:
    p = _which_or_raise("python3", TailNotAvailableError)
    assert p.startswith("/")


def test_which_or_raise_missing_raises() -> None:
    with pytest.raises(TailNotAvailableError):
        _which_or_raise("definitely-not-a-bin-xyz", TailNotAvailableError)


# --- tail_log ---------------------------------------------------------------


def test_tail_log_reads_last_lines(tmp_path: Path, tmp_token_file: Path) -> None:
    log_dir = tmp_path / "wlog"
    log_dir.mkdir()
    log_file = log_dir / "app.log"
    log_file.write_text("\n".join(f"line {i}" for i in range(50)) + "\n")
    cfg = _system_cfg(tmp_path, tmp_token_file, log_paths=[log_dir])

    result = tail_log(cfg, log_file, lines=5)
    assert result["source"] == str(log_file.resolve(strict=True))
    assert result["lines_requested"] == 5
    assert result["content_truncated"] is False
    assert result["exit_code"] == 0
    assert result["content"].count("line ") == 5
    assert "line 49" in result["content"]
    assert "line 0\n" not in result["content"]


def test_tail_log_default_lines_is_100(
    tmp_path: Path, tmp_token_file: Path
) -> None:
    log_dir = tmp_path / "wlog"
    log_dir.mkdir()
    log_file = log_dir / "app.log"
    log_file.write_text("\n".join(f"l{i}" for i in range(200)) + "\n")
    cfg = _system_cfg(tmp_path, tmp_token_file, log_paths=[log_dir])

    result = tail_log(cfg, log_file)
    assert result["lines_requested"] == DEFAULT_LOG_LINES


def test_tail_log_path_not_in_whitelist_rejected(
    tmp_path: Path, tmp_token_file: Path
) -> None:
    log_dir = tmp_path / "wlog"
    log_dir.mkdir()
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    bad = elsewhere / "x.log"
    bad.write_text("nope", encoding="utf-8")
    cfg = _system_cfg(tmp_path, tmp_token_file, log_paths=[log_dir])

    with pytest.raises(LogPathNotAllowedError):
        tail_log(cfg, bad)


def test_tail_log_path_traversal_rejected(
    tmp_path: Path, tmp_token_file: Path
) -> None:
    """Path traversal tipo /var/log/whitelist/../../etc/passwd → resolve
    porta fuori dal root → reject."""
    log_dir = tmp_path / "wlog"
    log_dir.mkdir()
    # Creiamo /etc/passwd-like fuori
    elsewhere = tmp_path / "outside"
    elsewhere.mkdir()
    target = elsewhere / "passwd"
    target.write_text("root:x:0:0", encoding="utf-8")
    traversal = log_dir / ".." / "outside" / "passwd"
    cfg = _system_cfg(tmp_path, tmp_token_file, log_paths=[log_dir])

    with pytest.raises(LogPathNotAllowedError):
        tail_log(cfg, traversal)


def test_tail_log_symlink_escaping_whitelist_rejected(
    tmp_path: Path, tmp_token_file: Path
) -> None:
    """Symlink dentro la whitelist che punta a file fuori → reject.
    Bypass classico: /var/log/devbox-bridge/x → /etc/passwd."""
    log_dir = tmp_path / "wlog"
    log_dir.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    secret = outside / "secret.txt"
    secret.write_text("classified", encoding="utf-8")
    link = log_dir / "innocent.log"
    link.symlink_to(secret)
    cfg = _system_cfg(tmp_path, tmp_token_file, log_paths=[log_dir])

    with pytest.raises(LogPathNotAllowedError):
        tail_log(cfg, link)


def test_tail_log_nonexistent_raises_log_path_not_found(
    tmp_path: Path, tmp_token_file: Path
) -> None:
    log_dir = tmp_path / "wlog"
    log_dir.mkdir()
    cfg = _system_cfg(tmp_path, tmp_token_file, log_paths=[log_dir])
    with pytest.raises(LogPathNotFoundError):
        tail_log(cfg, log_dir / "missing.log")


def test_tail_log_lines_out_of_range(
    tmp_path: Path, tmp_token_file: Path
) -> None:
    log_dir = tmp_path / "wlog"
    log_dir.mkdir()
    log_file = log_dir / "x.log"
    log_file.write_text("ok\n", encoding="utf-8")
    cfg = _system_cfg(tmp_path, tmp_token_file, log_paths=[log_dir])

    with pytest.raises(LinesOutOfRangeError):
        tail_log(cfg, log_file, lines=0)
    with pytest.raises(LinesOutOfRangeError):
        tail_log(cfg, log_file, lines=MAX_LOG_LINES + 1)


def test_tail_log_empty_whitelist_blocks_everything(
    tmp_path: Path, tmp_token_file: Path
) -> None:
    """Whitelist esplicitamente vuota → fail-secure: nessun path accessibile."""
    log_dir = tmp_path / "wlog"
    log_dir.mkdir()
    log_file = log_dir / "x.log"
    log_file.write_text("data", encoding="utf-8")
    cfg = _system_cfg(tmp_path, tmp_token_file, log_paths=[])

    with pytest.raises(LogPathNotAllowedError):
        tail_log(cfg, log_file)


def test_tail_log_output_truncated_at_max_bytes(
    tmp_path: Path, tmp_token_file: Path
) -> None:
    """Output del tail > MAX_LOG_OUTPUT_BYTES (512KB) → truncated. Per
    starci sotto MAX_LOG_LINES (5000) usiamo righe lunghe (200 char)."""
    log_dir = tmp_path / "wlog"
    log_dir.mkdir()
    log_file = log_dir / "huge.log"
    # 5000 righe * 201 bytes ≈ 1 MB > 512 KB
    line = "X" * 200 + "\n"
    log_file.write_text(line * MAX_LOG_LINES, encoding="utf-8")
    cfg = _system_cfg(tmp_path, tmp_token_file, log_paths=[log_dir])

    result = tail_log(cfg, log_file, lines=MAX_LOG_LINES)
    assert result["content_truncated"] is True
    assert len(result["content"].encode("utf-8")) <= MAX_LOG_OUTPUT_BYTES


def test_tail_log_relative_path_rejected(
    tmp_path: Path, tmp_token_file: Path
) -> None:
    """Path relativo non assoluto → reject (resolve_within_any pre-condizione)."""
    log_dir = tmp_path / "wlog"
    log_dir.mkdir()
    cfg = _system_cfg(tmp_path, tmp_token_file, log_paths=[log_dir])
    with pytest.raises(LogPathNotAllowedError):
        tail_log(cfg, "relative.log")


# --- read_journalctl --------------------------------------------------------


def test_read_journalctl_unit_not_in_whitelist_rejected(
    tmp_path: Path, tmp_token_file: Path
) -> None:
    cfg = _system_cfg(tmp_path, tmp_token_file, units=["allowed.service"])
    with pytest.raises(JournalctlUnitNotAllowedError):
        read_journalctl(cfg, "other.service")


def test_read_journalctl_unit_invalid_regex_rejected(
    tmp_path: Path, tmp_token_file: Path
) -> None:
    """Caratteri non ammessi nel nome unit → reject (defense-in-depth)."""
    cfg = _system_cfg(tmp_path, tmp_token_file, units=["devbox-bridge.service"])
    with pytest.raises(JournalctlUnitNotAllowedError):
        read_journalctl(cfg, "bad name; rm -rf /")


def test_read_journalctl_lines_out_of_range(
    tmp_path: Path, tmp_token_file: Path
) -> None:
    cfg = _system_cfg(tmp_path, tmp_token_file, units=["devbox-bridge.service"])
    with pytest.raises(LinesOutOfRangeError):
        read_journalctl(cfg, "devbox-bridge.service", lines=0)


def test_read_journalctl_journalctl_missing_raises(
    tmp_path: Path,
    tmp_token_file: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cfg = _system_cfg(tmp_path, tmp_token_file, units=["devbox-bridge.service"])
    monkeypatch.setattr("devbox_bridge.tools.system.shutil.which", lambda _: None)
    with pytest.raises(JournalctlNotAvailableError):
        read_journalctl(cfg, "devbox-bridge.service")


def test_read_journalctl_real_invocation_returns_response(
    tmp_path: Path, tmp_token_file: Path
) -> None:
    """Smoke: chiama journalctl reale su una unit esistente del sistema.
    Skip se journalctl non disponibile (es. CI senza systemd)."""
    if shutil.which("journalctl") is None:
        pytest.skip("journalctl non disponibile")
    # systemd-journald.service è quasi certamente presente sotto qualsiasi
    # distro con systemd; se non lo è, lo skip è giustificato.
    cfg = _system_cfg(
        tmp_path,
        tmp_token_file,
        units=["systemd-journald.service"],
    )
    result = read_journalctl(cfg, "systemd-journald.service", lines=3)
    assert result["source"] == "journalctl:systemd-journald.service"
    assert result["lines_requested"] == 3
    assert "content" in result


# --- list_systemd_services --------------------------------------------------


def test_list_systemd_services_default_filter_used(
    tmp_path: Path, tmp_token_file: Path
) -> None:
    if shutil.which("systemctl") is None:
        pytest.skip("systemctl non disponibile")
    cfg = _system_cfg(tmp_path, tmp_token_file, filter_default="systemd-")
    result = list_systemd_services(cfg)
    assert result["filter"] == "systemd-"
    # Su sistema con systemd, almeno systemd-journald.service deve esserci.
    units = [s["unit"] for s in result["services"]]
    assert any("systemd-" in u for u in units)


def test_list_systemd_services_custom_filter(
    tmp_path: Path, tmp_token_file: Path
) -> None:
    if shutil.which("systemctl") is None:
        pytest.skip("systemctl non disponibile")
    cfg = _system_cfg(tmp_path, tmp_token_file)
    result = list_systemd_services(cfg, name_filter="cron")
    assert result["filter"] == "cron"
    # tutte le unit returned contengono "cron"
    for s in result["services"]:
        assert "cron" in s["unit"]


def test_list_systemd_services_empty_filter_returns_all(
    tmp_path: Path, tmp_token_file: Path
) -> None:
    if shutil.which("systemctl") is None:
        pytest.skip("systemctl non disponibile")
    cfg = _system_cfg(tmp_path, tmp_token_file, filter_default="")
    result = list_systemd_services(cfg)
    # nessun filtro applicato → lista non vuota
    assert len(result["services"]) > 0


@pytest.mark.parametrize(
    "bad_filter",
    [
        "; rm -rf /",
        "$(whoami)",
        "' OR 1=1 --",
        "foo bar",
        "a|b",
        "back`tick",
    ],
)
def test_list_systemd_services_filter_pattern_injection_rejected(
    tmp_path: Path, tmp_token_file: Path, bad_filter: str
) -> None:
    """Filter con shell metachar / injection → FilterPatternError.
    Defense-in-depth (subprocess è già shell=False)."""
    cfg = _system_cfg(tmp_path, tmp_token_file)
    with pytest.raises(FilterPatternError):
        list_systemd_services(cfg, name_filter=bad_filter)


def test_list_systemd_services_systemctl_missing_raises(
    tmp_path: Path,
    tmp_token_file: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cfg = _system_cfg(tmp_path, tmp_token_file)
    monkeypatch.setattr("devbox_bridge.tools.system.shutil.which", lambda _: None)
    with pytest.raises(SystemctlNotAvailableError):
        list_systemd_services(cfg)


# --- get_system_info --------------------------------------------------------


def test_get_system_info_hostname_present() -> None:
    info = get_system_info()
    assert isinstance(info["hostname"], str)
    assert len(info["hostname"]) > 0


def test_get_system_info_kernel_arch_present_on_linux() -> None:
    info = get_system_info()
    assert info["kernel"] is not None
    assert info["arch"] is not None


def test_get_system_info_uptime_seconds_is_int() -> None:
    info = get_system_info()
    assert info["uptime_seconds"] is not None
    assert isinstance(info["uptime_seconds"], int)
    assert info["uptime_seconds"] >= 0


def test_get_system_info_load_has_three_keys() -> None:
    info = get_system_info()
    assert set(info["load"].keys()) >= {"1", "5", "15"}
    for v in info["load"].values():
        assert isinstance(v, float)


def test_get_system_info_memory_in_bytes() -> None:
    info = get_system_info()
    total = info["memory_bytes"]["total"]
    assert isinstance(total, int)
    # Una macchina sana ha almeno 256 MB. Le devbox tipicamente 16 GB.
    assert total > 256 * 1024 * 1024


def test_get_system_info_disk_is_list() -> None:
    info = get_system_info()
    assert isinstance(info["disk"], list)
    if info["disk"]:
        d = info["disk"][0]
        for key in ("source", "size", "used", "avail", "use_pct", "mount"):
            assert key in d
            assert isinstance(d[key], str)


def test_get_system_info_resilient_to_df_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Se df fallisce (non disponibile o non risponde), il tool non solleva:
    `disk` resta lista vuota."""
    real_which = shutil.which

    def fake_which(name: str) -> str | None:
        if name == "df":
            return None
        return real_which(name)

    monkeypatch.setattr("devbox_bridge.tools.system.shutil.which", fake_which)
    info = get_system_info()
    assert info["disk"] == []
    # Altri campi devono restare popolati
    assert info["hostname"] is not None
    assert info["kernel"] is not None


def test_get_system_info_resilient_to_uname_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_which = shutil.which

    def fake_which(name: str) -> str | None:
        if name == "uname":
            return None
        return real_which(name)

    monkeypatch.setattr("devbox_bridge.tools.system.shutil.which", fake_which)
    info = get_system_info()
    assert info["kernel"] is None
    assert info["arch"] is None
    # Altri campi /proc devono restare
    assert info["uptime_seconds"] is not None


def test_get_system_info_resilient_to_subprocess_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Se subprocess solleva SubprocessError generico (es. signal), il tool
    non solleva: campi opzionali restano default."""

    def boom(*_args: Any, **_kwargs: Any) -> None:
        raise subprocess.SubprocessError("boom")

    monkeypatch.setattr("devbox_bridge.tools.system._run", boom)
    info = get_system_info()
    # df/uname falliscono → kernel/arch/disk vuoti
    assert info["kernel"] is None
    assert info["disk"] == []
    # Ma hostname (no subprocess) e /proc reads sopravvivono
    assert info["hostname"] is not None
    assert info["uptime_seconds"] is not None
