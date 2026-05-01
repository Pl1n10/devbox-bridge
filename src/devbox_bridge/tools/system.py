"""Tool MCP — sistema (read-only).

Tool implementati nello step 10. Nessuno richiede write_enabled (sono
tutti read), ma sono auditati come read events (vedi audit.py).

PII / multi-tenant note:
  Questi tool espongono info di sistema (hostname, kernel, df totals, lista
  servizi systemd, contenuto file di log) NON sensibili nel modello
  single-tenant attuale (utente unico hypn0 sulla devbox). Un eventuale
  refactoring multi-tenant richiederebbe filtering aggiuntivo: hide-mounts
  per tenant, namespace-scoped systemctl, log path partition. Out of scope
  per l'MVP.

Tool:
  - get_system_info()                          → hostname/kernel/uptime/load/mem/disk
  - list_systemd_services(name_filter=None)    → lista unit filtrate
  - tail_log(path, lines=100)                  → tail di file in whitelist
  - read_journalctl(unit, lines=100)           → journalctl -u UNIT in whitelist

Validazione:
  - tail_log: path passa resolve_within_any contro system.log_paths_whitelist.
    Symlink che escono dalla whitelist sono rifiutati (resolve strict=True).
  - read_journalctl: unit deve matchare regex stretta E essere in
    system.systemd_unit_whitelist (doppio gate: validazione sintattica +
    autorizzazione esplicita).
  - list_systemd_services: name_filter validato con stessa regex (defense-in-depth
    contro injection in argomenti CLI, anche se subprocess è shell=False).

Invarianti:
  - subprocess.run con lista args, mai shell=True.
  - cwd=None (system-wide, non per-progetto).
  - env sanitizzato via security.env.sanitize_env() (anche per read, coerenza).
  - stdin=DEVNULL.
  - timeout SYSTEM_TIMEOUT_SECONDS=30s.

Mapping eccezioni → server outcome:
  LogPathNotAllowedError, JournalctlUnitNotAllowedError → "denied"
    (event "path.rejected" / "tool.<name>")
  LogPathNotFoundError, *NotAvailableError, FilterPatternError,
  LinesOutOfRangeError                                  → "error"
"""

from __future__ import annotations

import re
import shutil
import socket
import subprocess
from pathlib import Path
from typing import Any

from devbox_bridge.config import AppConfig
from devbox_bridge.security.env import get_current_env, sanitize_env
from devbox_bridge.security.paths import PathSecurityError, resolve_within_any

# --- Costanti ---------------------------------------------------------------

# Timeout per ogni subprocess (uname/df/tail/systemctl/journalctl). 30s è
# largo: tutti questi comandi rispondono in millisecondi su sistema sano,
# secondi al massimo se il filesystem è sotto stress.
SYSTEM_TIMEOUT_SECONDS: int = 30

# Default righe di log richieste per tail_log/read_journalctl. Match brief.
DEFAULT_LOG_LINES: int = 100

# Cap sul numero di righe richieste dal client. Indipendente dal limite
# byte sotto: 5000 righe da 200 char = 1 MB potenziale, ma stdout viene
# poi troncato a MAX_LOG_OUTPUT_BYTES.
MAX_LOG_LINES: int = 5000

# Cap sul payload di output della response. 512 KB ≈ metà di un context
# window 200K-token. Sopra questo limite il client deve iterare con `lines`
# minore (no `tail -n 5000` di un log da 200ch/riga = 1 MB).
MAX_LOG_OUTPUT_BYTES: int = 512 * 1024

# Regex stretta per nomi unit/filter passati ai subprocess. Defense-in-depth
# rispetto a config (che valida la whitelist al boot): qui validiamo input
# RUNTIME (filter di list_systemd_services arriva dal client MCP).
_NAME_RE = re.compile(r"^[A-Za-z0-9._@:-]{1,64}$")

# Filesystem virtuali/kernel da escludere dal df: non sono mount reali,
# sporcano l'output, variano frequentemente. Lista volutamente conservativa
# (filtro solo i fs noti come "non-disk"); aggiungere se ne emergono altri.
_DF_EXCLUDED_FS: tuple[str, ...] = (
    "tmpfs",
    "devtmpfs",
    "squashfs",
    "overlay",
    "efivarfs",
    "fusectl",
    "proc",
    "sysfs",
)


# --- Eccezioni --------------------------------------------------------------


class LogPathNotAllowedError(PermissionError):
    """Path richiesto non è dentro nessun root in system.log_paths_whitelist."""


class LogPathNotFoundError(FileNotFoundError):
    """Path è whitelistato ma il file non esiste."""


class JournalctlUnitNotAllowedError(PermissionError):
    """Unit non è in system.systemd_unit_whitelist (o non passa la regex)."""


class FilterPatternError(ValueError):
    """Filter di list_systemd_services contiene caratteri non ammessi."""


class LinesOutOfRangeError(ValueError):
    """`lines` fuori da [1, MAX_LOG_LINES]."""


class TailNotAvailableError(RuntimeError):
    """`tail` non trovato nel PATH."""


class SystemctlNotAvailableError(RuntimeError):
    """`systemctl` non trovato nel PATH."""


class JournalctlNotAvailableError(RuntimeError):
    """`journalctl` non trovato nel PATH."""


# --- Helper privati ---------------------------------------------------------


def _which_or_raise(binary: str, exc: type[RuntimeError]) -> str:
    p = shutil.which(binary)
    if p is None:
        raise exc(f"{binary} non trovato nel PATH")
    return p


def _check_lines(lines: int) -> int:
    # bool è subclass di int → escludo esplicitamente.
    if not isinstance(lines, int) or isinstance(lines, bool):
        raise LinesOutOfRangeError(
            f"lines deve essere int, ho {type(lines).__name__}"
        )
    if lines < 1 or lines > MAX_LOG_LINES:
        raise LinesOutOfRangeError(
            f"lines={lines} fuori da [1, {MAX_LOG_LINES}]"
        )
    return lines


def _validate_name_or_raise(name: str, exc: type[Exception], label: str) -> None:
    if not _NAME_RE.fullmatch(name):
        raise exc(f"{label} '{name}' contiene caratteri non ammessi")


def _build_env() -> dict[str, str]:
    return sanitize_env(get_current_env())


def _truncate_bytes(text: str, max_bytes: int) -> tuple[str, bool]:
    encoded = text.encode("utf-8", errors="replace")
    if len(encoded) <= max_bytes:
        return text, False
    truncated = encoded[:max_bytes].decode("utf-8", errors="replace")
    return truncated, True


def _run(argv: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 — argv da shutil.which o letterali
        argv,
        cwd=None,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=SYSTEM_TIMEOUT_SECONDS,
        check=False,
        env=_build_env(),
    )


# --- Tool pubblici ----------------------------------------------------------


def tail_log(
    cfg: AppConfig,
    path: str | Path,
    lines: int = DEFAULT_LOG_LINES,
) -> dict[str, Any]:
    """Esegue `tail -n <lines> <path>` su un file in whitelist.

    Validazione (in ordine):
      1. lines in [1, MAX_LOG_LINES] (else LinesOutOfRangeError).
      2. path assoluto + esistente + dentro almeno un root in
         system.log_paths_whitelist (else LogPathNotAllowedError /
         LogPathNotFoundError).
      3. `tail` disponibile nel PATH (else TailNotAvailableError).

    Output troncato a MAX_LOG_OUTPUT_BYTES con flag `content_truncated`.
    """
    _check_lines(lines)
    try:
        resolved = resolve_within_any(path, cfg.system.log_paths_whitelist)
    except FileNotFoundError as e:
        raise LogPathNotFoundError(f"log path '{path}' non esiste") from e
    except PathSecurityError as e:
        raise LogPathNotAllowedError(str(e)) from e

    tail_bin = _which_or_raise("tail", TailNotAvailableError)
    proc = _run([tail_bin, "-n", str(lines), str(resolved)])

    content, truncated = _truncate_bytes(proc.stdout, MAX_LOG_OUTPUT_BYTES)
    return {
        "source": str(resolved),
        "lines_requested": lines,
        "exit_code": proc.returncode,
        "content": content,
        "content_truncated": truncated,
    }


def read_journalctl(
    cfg: AppConfig,
    unit: str,
    lines: int = DEFAULT_LOG_LINES,
) -> dict[str, Any]:
    """Esegue `journalctl -u <unit> -n <lines> --no-pager` per unit in whitelist.

    Validazione (in ordine):
      1. lines in [1, MAX_LOG_LINES] (else LinesOutOfRangeError).
      2. unit matcha regex stretta (defense-in-depth, prima del whitelist
         check) (else JournalctlUnitNotAllowedError).
      3. unit in system.systemd_unit_whitelist (else
         JournalctlUnitNotAllowedError).
      4. `journalctl` disponibile nel PATH (else JournalctlNotAvailableError).

    Permessi: l'utente del bridge deve avere accesso al journal system-wide.
    Su Ubuntu, l'appartenenza ai gruppi `adm` o `systemd-journal` è
    sufficiente. Se il processo gira sotto utente con accesso ridotto,
    journalctl ritornerà output vuoto / `-- No entries --` per unit non
    accessibili (no eccezione, ma `content` vuoto).
    """
    _check_lines(lines)
    _validate_name_or_raise(unit, JournalctlUnitNotAllowedError, "unit")
    if unit not in cfg.system.systemd_unit_whitelist:
        raise JournalctlUnitNotAllowedError(
            f"unit '{unit}' non è in systemd_unit_whitelist"
        )

    journalctl_bin = _which_or_raise("journalctl", JournalctlNotAvailableError)
    proc = _run(
        [journalctl_bin, "-u", unit, "-n", str(lines), "--no-pager"]
    )

    content, truncated = _truncate_bytes(proc.stdout, MAX_LOG_OUTPUT_BYTES)
    return {
        "source": f"journalctl:{unit}",
        "lines_requested": lines,
        "exit_code": proc.returncode,
        "content": content,
        "content_truncated": truncated,
    }


def list_systemd_services(
    cfg: AppConfig,
    name_filter: str | None = None,
) -> dict[str, Any]:
    """Esegue `systemctl list-units --type=service --all --no-pager --plain --no-legend`
    e filtra per substring sul nome unit.

    `name_filter`:
      - None → usa system.systemd_filter_default (può essere stringa vuota
        = nessun filtro).
      - stringa → validata con _NAME_RE (else FilterPatternError, anche se
        subprocess è shell=False — defense-in-depth contro injection).
      - stringa vuota → nessun filtro (ritorna tutte le service unit).

    Nota: `name_filter` (non `filter`) per evitare lo shadowing del builtin.
    """
    actual = (
        name_filter
        if name_filter is not None
        else cfg.system.systemd_filter_default
    )
    if actual:
        _validate_name_or_raise(actual, FilterPatternError, "filter")

    systemctl_bin = _which_or_raise("systemctl", SystemctlNotAvailableError)
    proc = _run(
        [
            systemctl_bin,
            "list-units",
            "--type=service",
            "--all",
            "--no-pager",
            "--plain",
            "--no-legend",
        ]
    )

    services: list[dict[str, str]] = []
    for line in proc.stdout.splitlines():
        # Format: UNIT LOAD ACTIVE SUB DESCRIPTION
        parts = line.split(None, 4)
        if len(parts) < 4:
            continue
        unit_name = parts[0]
        if actual and actual not in unit_name:
            continue
        services.append(
            {
                "unit": unit_name,
                "load": parts[1],
                "active": parts[2],
                "sub": parts[3],
                "description": parts[4] if len(parts) >= 5 else "",
            }
        )

    return {
        "filter": actual,
        "exit_code": proc.returncode,
        "services": services,
    }


def get_system_info() -> dict[str, Any]:
    """Aggregato read-only di info sistema. Resiliente a fallimenti parziali:
    se un sub-step fallisce (binario assente, /proc non leggibile), il
    campo corrispondente resta al default (None / dict vuoto / lista vuota)
    ma il tool NON solleva.

    Schema:
      hostname:        str
      kernel:          str | None  (uname -s)
      arch:            str | None  (uname -m)
      uptime_seconds:  int | None  (parte intera di /proc/uptime)
      load:            {"1","5","15": float}  (/proc/loadavg)
      memory_bytes:    {"total","available","free": int | None}
                       (kB di /proc/meminfo × 1024 → byte)
      disk:            list[{"source","size","used","avail","use_pct","mount": str}]
                       Campi DELIBERATAMENTE human-readable (df -h). Non
                       parsare numericamente — se servono byte raw, in
                       futuro aggiungere `disk_bytes` come campo separato.
    """
    info: dict[str, Any] = {
        "hostname": socket.gethostname(),
        "kernel": None,
        "arch": None,
        "uptime_seconds": None,
        "load": {},
        "memory_bytes": {},
        "disk": [],
    }

    # uname -srm → "Linux 6.8.0-110-generic x86_64"
    uname_bin = shutil.which("uname")
    if uname_bin:
        try:
            r = _run([uname_bin, "-srm"])
            if r.returncode == 0:
                parts = r.stdout.strip().split()
                if len(parts) >= 3:
                    info["kernel"] = parts[1]
                    info["arch"] = parts[2]
        except subprocess.SubprocessError:
            pass

    # /proc/uptime: "<uptime_seconds> <idle_seconds>"
    try:
        text = Path("/proc/uptime").read_text(encoding="utf-8")
        info["uptime_seconds"] = int(float(text.split()[0]))
    except (FileNotFoundError, ValueError, IndexError, OSError):
        pass

    # /proc/loadavg: "1m 5m 15m running/total lastpid"
    try:
        text = Path("/proc/loadavg").read_text(encoding="utf-8")
        parts = text.split()
        info["load"] = {
            "1": float(parts[0]),
            "5": float(parts[1]),
            "15": float(parts[2]),
        }
    except (FileNotFoundError, ValueError, IndexError, OSError):
        pass

    # /proc/meminfo: chiavi tipo "MemTotal:    16356212 kB"
    try:
        text = Path("/proc/meminfo").read_text(encoding="utf-8")
        meminfo: dict[str, int] = {}
        for line in text.splitlines():
            if ":" not in line:
                continue
            key, _, val = line.partition(":")
            val = val.strip()
            if not val.endswith("kB"):
                continue
            try:
                meminfo[key.strip()] = int(val.removesuffix("kB").strip()) * 1024
            except ValueError:
                continue
        info["memory_bytes"] = {
            "total": meminfo.get("MemTotal"),
            "available": meminfo.get("MemAvailable"),
            "free": meminfo.get("MemFree"),
        }
    except (FileNotFoundError, OSError):
        pass

    # df -h con esclusione fs virtuali. Output human-readable, non parsato
    # numericamente — se servono byte raw, aggiungere disk_bytes separato.
    df_bin = shutil.which("df")
    if df_bin:
        try:
            argv = [df_bin, "-h", "--output=source,size,used,avail,pcent,target"]
            for fs in _DF_EXCLUDED_FS:
                argv.extend(["-x", fs])
            r = _run(argv)
            if r.returncode == 0:
                disk: list[dict[str, str]] = []
                # Prima riga = header, scarta.
                for line in r.stdout.splitlines()[1:]:
                    parts = line.split()
                    if len(parts) >= 6:
                        disk.append(
                            {
                                "source": parts[0],
                                "size": parts[1],
                                "used": parts[2],
                                "avail": parts[3],
                                "use_pct": parts[4],
                                "mount": parts[5],
                            }
                        )
                info["disk"] = disk
        except subprocess.SubprocessError:
            pass

    return info
