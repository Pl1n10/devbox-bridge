"""Tool MCP — filesystem.

Sei tool esposti dal server (registrazione effettiva nello step 7):
  - list_projects: enumera progetti dal config (esposizione minimal).
  - read_file: leggi un file di testo dentro la project root.
  - write_file: scrivi/sovrascrivi un file (richiede project.write_enabled).
  - apply_patch: str-replace su un file (richiede project.write_enabled).
  - list_directory: elenca entry di una directory dentro il progetto.
  - search_files: ripgrep wrapper su file di testo dentro il progetto.

Invarianti applicate da TUTTI i tool:
  - Ogni path passa da `security.paths.resolve_within` → traversal e symlink
    che escono → `PathSecurityError`.
  - I path nei JSON di output sono SEMPRE relativi alla project root (no
    info disclosure sulla struttura assoluta del filesystem).
  - I tool non scrivono mai sul logger di audit: lo fa il caller (server)
    perché ha contesto auth/client_ip. Le eccezioni sollevate qui hanno
    classi specifiche per facilitare il mapping outcome lato server:
      PathSecurityError    → "denied" + event="path.rejected"
      WriteNotAllowedError → "denied" + event="path.rejected"
      OSError family       → "error"
      success              → "success"

Limiti read:
  - max_read_bytes = project.max_read_bytes or DEFAULT_MAX_READ_BYTES (10 MB).
  - Hard ceiling configurabile è 50 MB (ProjectConfig). Motivazione: il
    content torna inline nel JSON response MCP — oltre questa soglia satura
    il context window di qualunque client.

Binari:
  - Euristica: byte 0x00 nei primi 8 KB → file binario.
  - read_file e apply_patch rifiutano i binari (BinaryFileError).
  - search_files: lasciato a ripgrep (default skip binari).

Encoding:
  - UTF-8 strict per read_file / apply_patch. Errori di decode sollevati
    espliciti come UnicodeDecodeError (non sostituiamo silenziosamente).
"""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

from devbox_bridge.config import AppConfig, ProjectConfig
from devbox_bridge.security.paths import PathSecurityError, resolve_within

DEFAULT_MAX_READ_BYTES: int = 10 * 1024 * 1024  # 10 MB
BINARY_SNIFF_BYTES: int = 8 * 1024  # 8 KB
RG_TIMEOUT_SECONDS: int = 30

SKIP_DIRS: frozenset[str] = frozenset(
    {
        ".git",
        "node_modules",
        "__pycache__",
        ".venv",
        "venv",
        "dist",
        "build",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
        ".next",
        "target",
        ".tox",
        "vendor",
        ".gradle",
    }
)


# --- Eccezioni specifiche del modulo ----------------------------------------


class WriteNotAllowedError(PermissionError):
    """Tool write invocato su progetto con write_enabled=False."""


class BinaryFileError(ValueError):
    """File binario passato a un tool che richiede testo."""


class FileTooLargeError(ValueError):
    """File supera max_read_bytes effettivo per il progetto."""


class GlobSecurityError(ValueError):
    """Glob di search_files contiene path traversal o path assoluto."""


class RipgrepNotFoundError(RuntimeError):
    """`rg` non installato sul sistema."""


# --- Helper privati ---------------------------------------------------------


def _project(cfg: AppConfig, project: str) -> ProjectConfig:
    return cfg.project(project)


def _project_root(proj: ProjectConfig) -> Path:
    return proj.path.resolve(strict=True)


def _max_read_bytes(proj: ProjectConfig) -> int:
    return proj.max_read_bytes if proj.max_read_bytes is not None else DEFAULT_MAX_READ_BYTES


def _looks_binary(data: bytes) -> bool:
    return b"\x00" in data[:BINARY_SNIFF_BYTES]


def _sha8(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()[:8]


def _rel_to_root(path: Path, root: Path) -> str:
    """Path relativo a root, o '<external>' se non relativo (non dovrebbe
    accadere dopo resolve_within, ma difensivo)."""
    try:
        rel = path.relative_to(root)
    except ValueError:
        return "<external>"
    s = str(rel)
    return s if s != "" else "."


def _decode_utf8_strict(data: bytes, rel_path: str) -> str:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as e:
        raise UnicodeDecodeError(
            e.encoding,
            e.object,
            e.start,
            e.end,
            f"file '{rel_path}' non è UTF-8 valido: {e.reason}",
        ) from None


def _ensure_writable(proj: ProjectConfig, project_name: str) -> None:
    if not proj.write_enabled:
        raise WriteNotAllowedError(
            f"project '{project_name}' ha write_enabled=False"
        )


# --- list_projects ----------------------------------------------------------


def list_projects(cfg: AppConfig) -> list[dict[str, Any]]:
    """Esposizione minimale dei progetti. NIENTE command_whitelist /
    env_passthrough: sono dettagli interni di sicurezza."""
    out: list[dict[str, Any]] = []
    for name, proj in cfg.projects.items():
        out.append(
            {
                "name": name,
                "path": str(proj.path),
                "write_enabled": proj.write_enabled,
                "allow_push": proj.allow_push,
                "has_test_command": proj.test_command is not None,
                "has_lint_command": proj.lint_command is not None,
                "has_build_command": proj.build_command is not None,
            }
        )
    return out


# --- read_file --------------------------------------------------------------


def read_file(cfg: AppConfig, project: str, rel_path: str) -> dict[str, Any]:
    proj = _project(cfg, project)
    root = _project_root(proj)
    target = resolve_within(proj.path, rel_path)

    if not target.exists():
        raise FileNotFoundError(f"file '{rel_path}' non trovato")
    if not target.is_file():
        raise IsADirectoryError(f"'{rel_path}' non è un file regolare")

    size = target.stat().st_size
    max_bytes = _max_read_bytes(proj)
    if size > max_bytes:
        raise FileTooLargeError(
            f"file '{rel_path}' è {size} bytes, max {max_bytes}"
        )

    data = target.read_bytes()
    if _looks_binary(data):
        raise BinaryFileError(f"file '{rel_path}' è binario")

    content = _decode_utf8_strict(data, rel_path)

    return {
        "path": _rel_to_root(target, root),
        "bytes": size,
        "encoding": "utf-8",
        "content_sha8": _sha8(data),
        "content": content,
    }


# --- write_file -------------------------------------------------------------


def write_file(
    cfg: AppConfig,
    project: str,
    rel_path: str,
    content: str,
    *,
    create: bool = False,
) -> dict[str, Any]:
    """Scrive `content` in `rel_path`. Overwrite totale se il file esiste.

    Semantica `create`:
      - file esiste: il flag è ignorato, overwrite.
      - file non esiste: serve `create=True`; altrimenti FileNotFoundError.
    Le directory intermedie vengono create se `create=True`.
    """
    proj = _project(cfg, project)
    _ensure_writable(proj, project)
    root = _project_root(proj)
    target = resolve_within(proj.path, rel_path)

    if target.exists():
        if not target.is_file():
            raise IsADirectoryError(
                f"'{rel_path}' esiste e non è un file regolare"
            )
        existed = True
    else:
        if not create:
            raise FileNotFoundError(
                f"file '{rel_path}' non esiste; passa create=True per crearlo"
            )
        target.parent.mkdir(parents=True, exist_ok=True)
        existed = False

    data = content.encode("utf-8")
    target.write_bytes(data)

    return {
        "path": _rel_to_root(target, root),
        "bytes": len(data),
        "content_sha8": _sha8(data),
        "created": not existed,
    }


# --- apply_patch ------------------------------------------------------------


def apply_patch(
    cfg: AppConfig,
    project: str,
    rel_path: str,
    old: str,
    new: str,
) -> dict[str, Any]:
    """str.replace(old, new) atomico sul contenuto del file.

    Refuse:
      - old == new (no-op silenzioso).
      - file binario.
      - old non trovato nel file.
    """
    proj = _project(cfg, project)
    _ensure_writable(proj, project)

    if old == new:
        raise ValueError(
            "old e new sono identici: nessun cambiamento richiesto"
        )

    root = _project_root(proj)
    target = resolve_within(proj.path, rel_path)

    if not target.exists():
        raise FileNotFoundError(f"file '{rel_path}' non trovato")
    if not target.is_file():
        raise IsADirectoryError(f"'{rel_path}' non è un file regolare")

    data_before = target.read_bytes()
    if _looks_binary(data_before):
        raise BinaryFileError(f"file '{rel_path}' è binario")

    text_before = _decode_utf8_strict(data_before, rel_path)
    occurrences = text_before.count(old)
    if occurrences == 0:
        raise ValueError(f"old non trovato in '{rel_path}'")

    text_after = text_before.replace(old, new)
    data_after = text_after.encode("utf-8")
    target.write_bytes(data_after)

    return {
        "path": _rel_to_root(target, root),
        "occurrences_replaced": occurrences,
        "bytes_before": len(data_before),
        "bytes_after": len(data_after),
        "content_sha8_before": _sha8(data_before),
        "content_sha8_after": _sha8(data_after),
    }


# --- list_directory ---------------------------------------------------------


def list_directory(
    cfg: AppConfig,
    project: str,
    rel_path: str = ".",
) -> dict[str, Any]:
    """Elenco entry. Ogni entry ha `name` + `type` (file/dir/symlink/other).
    Per `dir`: aggiunge `skipped` (true se è in SKIP_DIRS, da non scendere).
    Per `file`: aggiunge `size`.
    Per `symlink`: aggiunge `target` come path relativo a root, oppure
    `<external>` se il symlink esce dalla project root (NON seguito).
    """
    proj = _project(cfg, project)
    root = _project_root(proj)
    target = resolve_within(proj.path, rel_path)

    if not target.exists():
        raise FileNotFoundError(f"directory '{rel_path}' non trovata")
    if not target.is_dir():
        raise NotADirectoryError(f"'{rel_path}' non è una directory")

    entries: list[dict[str, Any]] = []
    for child in sorted(target.iterdir(), key=lambda p: p.name):
        if child.is_symlink():
            entries.append(_describe_symlink(child, root))
        elif child.is_dir():
            entries.append(
                {
                    "name": child.name,
                    "type": "dir",
                    "skipped": child.name in SKIP_DIRS,
                }
            )
        elif child.is_file():
            try:
                size = child.stat().st_size
            except OSError:
                size = 0
            entries.append(
                {
                    "name": child.name,
                    "type": "file",
                    "size": size,
                }
            )
        else:
            entries.append({"name": child.name, "type": "other"})

    return {
        "path": _rel_to_root(target, root),
        "entries": entries,
    }


def _describe_symlink(child: Path, root: Path) -> dict[str, Any]:
    sym_target = "<external>"
    try:
        real = child.resolve(strict=False)
        try:
            rel = real.relative_to(root)
            sym_target = str(rel) or "."
        except ValueError:
            sym_target = "<external>"
    except (OSError, RuntimeError):
        sym_target = "<external>"
    return {
        "name": child.name,
        "type": "symlink",
        "target": sym_target,
    }


# --- search_files -----------------------------------------------------------


def _validate_glob(glob: str) -> None:
    """Rifiuta glob con path traversal o path assoluto.

    rg `--glob` accetta pattern type-fnmatch ('*.py', 'src/**'), negazione
    con '!', alternazione con '{a,b}'. Tutto OK. Quello che rifiutiamo è:
      - segmento '..' in qualsiasi posizione (escape verso parent dirs)
      - path assoluti ('/etc/*', '~/foo')
      - stringa vuota
    """
    if not glob:
        raise GlobSecurityError("glob vuoto")
    normalized = glob.replace("\\", "/")
    # Strip negation prefix per il check (il '!' è una direttiva rg, non parte del path)
    payload = normalized[1:] if normalized.startswith("!") else normalized
    if payload.startswith("/"):
        raise GlobSecurityError(f"glob '{glob}' è un path assoluto")
    if payload.startswith("~"):
        raise GlobSecurityError(f"glob '{glob}' è un path home-relative")
    parts = payload.split("/")
    if any(p == ".." for p in parts):
        raise GlobSecurityError(f"glob '{glob}' contiene segmento '..'")


def search_files(
    cfg: AppConfig,
    project: str,
    pattern: str,
    *,
    glob: str = "*",
    max_matches: int = 500,
) -> dict[str, Any]:
    """Wrapper su ripgrep. Output JSON con righe di match e path relativi.

    Skip dirs (oltre i default di rg): SKIP_DIRS. Skip binari: default rg.
    """
    if max_matches < 1:
        raise ValueError("max_matches deve essere >= 1")
    proj = _project(cfg, project)
    root = _project_root(proj)

    _validate_glob(glob)

    if shutil.which("rg") is None:
        raise RipgrepNotFoundError(
            "ripgrep (rg) non trovato nel PATH; "
            "installalo con `apt install ripgrep`"
        )

    args: list[str] = ["rg", "--json", "--glob", glob]
    for skip in sorted(SKIP_DIRS):
        args += ["--glob", f"!{skip}"]
    args += ["--", pattern, str(root)]

    try:
        proc = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=RG_TIMEOUT_SECONDS,
            cwd=str(root),
            check=False,
        )
    except subprocess.TimeoutExpired as e:
        raise RuntimeError(
            f"search_files: ripgrep ha superato {RG_TIMEOUT_SECONDS}s"
        ) from e

    # rg ritorna 1 quando non trova match → non è un errore.
    if proc.returncode not in (0, 1):
        raise RuntimeError(
            f"ripgrep failed (exit {proc.returncode}): {proc.stderr[:500]}"
        )

    matches: list[dict[str, Any]] = []
    truncated = False
    for line in proc.stdout.splitlines():
        if not line:
            continue
        try:
            evt = json.loads(line)
        except json.JSONDecodeError:
            continue
        if evt.get("type") != "match":
            continue
        data = evt.get("data") or {}
        path_text = (data.get("path") or {}).get("text") or ""
        rel = _rg_path_to_rel(path_text, root)
        line_no = data.get("line_number")
        lines_text = (data.get("lines") or {}).get("text") or ""
        matches.append(
            {
                "path": rel,
                "line": line_no,
                "text": lines_text.rstrip("\n"),
            }
        )
        if len(matches) >= max_matches:
            truncated = True
            break

    return {
        "pattern": pattern,
        "glob": glob,
        "matches": matches,
        "match_count": len(matches),
        "truncated": truncated,
    }


def _rg_path_to_rel(path_text: str, root: Path) -> str:
    if not path_text:
        return ""
    p = Path(path_text)
    if p.is_absolute():
        try:
            return str(p.relative_to(root))
        except ValueError:
            return path_text
    return path_text


__all__ = [
    "BINARY_SNIFF_BYTES",
    "DEFAULT_MAX_READ_BYTES",
    "SKIP_DIRS",
    "BinaryFileError",
    "FileTooLargeError",
    "GlobSecurityError",
    "PathSecurityError",
    "RipgrepNotFoundError",
    "WriteNotAllowedError",
    "apply_patch",
    "list_directory",
    "list_projects",
    "read_file",
    "search_files",
    "write_file",
]
