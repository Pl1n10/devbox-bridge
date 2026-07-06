"""Tool MCP — notes (step 13, vault Mnemosyne).

Espone il vault markdown `~/notes/` (working copy del repo Gitea `notes`)
come tool MCP. Spec: mnemosyne/notes-module/SPEC-step13-notes.md; vincoli
architetturali da ADR-008/009 di mnemosyne.

Read (ovunque nel vault):
  - notes_list        → lista file relativa, ordinata, max MAX_LIST_ENTRIES.
  - notes_read        → contenuto file .md (max max_read_bytes).
  - notes_search      → grep case-insensitive, `path:linea:testo`.

Write (solo sotto le write_dirs, default llm/ e inbox/):
  - notes_write       → pull --rebase → write → commit atomico → push.

Sync:
  - notes_sync_pull   → git pull --rebase --autostash.
  - notes_sync_status → fetch best-effort + porcelain v1 (ahead/behind).

Invarianti (non negoziabili):
  - Containment: ogni path passa da security.paths.resolve_within.
  - Write whitelist: primo componente del path relativo in cfg.write_dirs.
  - Pull PRIMA di ogni write; su conflitto: rebase --abort + NotesSyncError,
    il file NON viene scritto.
  - Un commit per write, messaggio `notes(mcp): <mode> <path>`.
  - MAI --force / -f nei comandi git (i test ispezionano gli argv).
  - Nessuna delete esposta (YAGNI + safety, la fa Roberto da PC).
  - subprocess.run con lista args, mai shell=True, env sanitizzato.
"""

from __future__ import annotations

import shutil
import subprocess
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from devbox_bridge.security.env import get_current_env, sanitize_env
from devbox_bridge.security.paths import resolve_within
from devbox_bridge.tools.filesystem import FileTooLargeError, WriteNotAllowedError
from devbox_bridge.tools.git import _parse_porcelain_v1

GIT_TIMEOUT_SECONDS: int = 60  # pull/push passano dalla rete (Tailscale)
MAX_LIST_ENTRIES: int = 500
MAX_SEARCH_LINES: int = 200
DEFAULT_MAX_READ_BYTES: int = 1_048_576  # 1 MB

_VALID_WRITE_MODES: frozenset[str] = frozenset({"create", "overwrite", "append"})

# Stati porcelain XY che indicano conflitto non risolto (unmerged).
_CONFLICT_CODES: frozenset[str] = frozenset({"DD", "AU", "UD", "UA", "DU", "AA", "UU"})


# --- Eccezioni ---------------------------------------------------------------


class NotesFileError(ValueError):
    """File non valido per il vault: non-.md, mancante, o create su esistente."""


class NotesSyncError(RuntimeError):
    """Sync git fallito (pull/push/conflitto): la write viene rifiutata."""


# --- Config ------------------------------------------------------------------


class NotesConfig(BaseModel):
    """Config del modulo notes. Volutamente separata da AppConfig: il vault
    non è un "project" (whitelist path e write policy sono diverse)."""

    model_config = ConfigDict(extra="forbid")

    root: Path
    write_dirs: tuple[str, ...] = ("llm", "inbox")
    max_read_bytes: int = Field(default=DEFAULT_MAX_READ_BYTES, gt=0)

    @field_validator("root")
    @classmethod
    def _root_absolute(cls, v: Path) -> Path:
        expanded = Path(v).expanduser()
        if not expanded.is_absolute():
            raise ValueError(f"NOTES_ROOT '{v}' deve essere assoluto")
        return expanded

    @field_validator("write_dirs")
    @classmethod
    def _write_dirs_relative(cls, v: tuple[str, ...]) -> tuple[str, ...]:
        for d in v:
            p = Path(d)
            if not d or p.is_absolute() or ".." in p.parts:
                raise ValueError(f"write_dir '{d}' non valido: deve essere relativo, senza '..'")
        return v

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> NotesConfig:
        if env is None:
            env = get_current_env()
        write_dirs = tuple(
            d.strip() for d in env.get("NOTES_WRITE_DIRS", "llm,inbox").split(",") if d.strip()
        )
        return cls(
            root=Path(env.get("NOTES_ROOT", "~/notes")),
            write_dirs=write_dirs,
            max_read_bytes=int(env.get("NOTES_MAX_READ_BYTES", str(DEFAULT_MAX_READ_BYTES))),
        )


# --- Helper privati ----------------------------------------------------------


class GitNotFoundError(RuntimeError):
    """`git` non trovato nel PATH."""


def _git_executable() -> str:
    p = shutil.which("git")
    if p is None:
        raise GitNotFoundError("git non trovato nel PATH; installa con `apt install git`")
    return p


def _vault_root(cfg: NotesConfig) -> Path:
    # resolve_within valida anche l'esistenza del root (strict=True).
    return resolve_within(cfg.root, ".")


def _git_env() -> dict[str, str]:
    env = sanitize_env(get_current_env())
    # No prompt interattivi (TTY/SSH/HTTP), no lock opportunistici.
    env.setdefault("GIT_TERMINAL_PROMPT", "0")
    env.setdefault("GIT_OPTIONAL_LOCKS", "0")
    return env


def _run_git(
    cfg: NotesConfig,
    args: list[str],
    *,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    full = [_git_executable(), "--no-pager", *args]
    try:
        proc = subprocess.run(  # noqa: S603 — git da shutil.which, args lista
            full,
            cwd=str(_vault_root(cfg)),
            capture_output=True,
            text=True,
            timeout=GIT_TIMEOUT_SECONDS,
            check=False,
            env=_git_env(),
        )
    except subprocess.TimeoutExpired as e:
        raise NotesSyncError(f"git {args[0]} in timeout dopo {GIT_TIMEOUT_SECONDS}s") from e

    if check and proc.returncode != 0:
        head = (proc.stderr or proc.stdout or "").strip().splitlines()
        first = head[0] if head else ""
        raise NotesSyncError(f"git {args[0]} → exit {proc.returncode}: {first[:300]}")
    return proc


def _resolve_md(cfg: NotesConfig, path: str) -> tuple[Path, Path]:
    """Containment + estensione. Ritorna (target risolto, path relativo)."""
    root = _vault_root(cfg)
    target = resolve_within(cfg.root, path)
    rel = target.relative_to(root)
    if target.suffix.lower() != ".md":
        raise NotesFileError(f"solo file .md nel vault: '{rel}'")
    return target, rel


def _ensure_tree_not_conflicted(cfg: NotesConfig) -> None:
    root = _vault_root(cfg)
    for marker in ("rebase-merge", "rebase-apply", "MERGE_HEAD"):
        if (root / ".git" / marker).exists():
            raise NotesSyncError(
                f"vault in stato {marker}: risolvere manualmente prima di scrivere"
            )
    proc = _run_git(cfg, ["status", "--porcelain=v1", "-z"])
    for entry in proc.stdout.split("\0"):
        if len(entry) >= 2 and entry[:2] in _CONFLICT_CODES:
            raise NotesSyncError(f"vault con conflitti non risolti ({entry[:2]} {entry[3:]})")


def _pull_rebase(cfg: NotesConfig) -> None:
    proc = _run_git(cfg, ["pull", "--rebase", "--autostash"], check=False)
    if proc.returncode != 0:
        # Best-effort: riporta il working tree allo stato pre-pull.
        _run_git(cfg, ["rebase", "--abort"], check=False)
        head = (proc.stderr or proc.stdout or "").strip().splitlines()
        first = head[0] if head else ""
        raise NotesSyncError(f"pull --rebase fallito (conflitto?): {first[:300]}")


def _current_branch(cfg: NotesConfig) -> str:
    proc = _run_git(cfg, ["symbolic-ref", "--short", "-q", "HEAD"], check=False)
    branch = proc.stdout.strip()
    if proc.returncode != 0 or not branch:
        raise NotesSyncError("HEAD detached nel vault: rifiuto push senza branch")
    return branch


def _head_sha(cfg: NotesConfig) -> str:
    return _run_git(cfg, ["rev-parse", "HEAD"]).stdout.strip()


def _iter_vault_files(root: Path, base: Path, glob: str) -> list[Path]:
    out: list[Path] = []
    for p in base.rglob(glob):
        if not p.is_file():
            continue
        if ".git" in p.relative_to(root).parts:
            continue
        out.append(p)
    return out


# --- notes_list ----------------------------------------------------------------


def notes_list(
    cfg: NotesConfig,
    subdir: str | None = None,
    glob: str = "*.md",
) -> dict[str, Any]:
    root = _vault_root(cfg)
    base = resolve_within(cfg.root, subdir or ".")
    files = sorted(str(p.relative_to(root)) for p in _iter_vault_files(root, base, glob))
    truncated = len(files) > MAX_LIST_ENTRIES
    files = files[:MAX_LIST_ENTRIES]
    return {"files": files, "count": len(files), "truncated": truncated}


# --- notes_read ----------------------------------------------------------------


def notes_read(cfg: NotesConfig, path: str) -> dict[str, Any]:
    target, rel = _resolve_md(cfg, path)
    if not target.is_file():
        raise NotesFileError(f"'{rel}' non esiste nel vault")
    size = target.stat().st_size
    if size > cfg.max_read_bytes:
        raise FileTooLargeError(f"'{rel}' è {size} byte, oltre il limite di {cfg.max_read_bytes}")
    content = target.read_text(encoding="utf-8", errors="replace")
    return {"path": str(rel), "bytes": size, "content": content}


# --- notes_search ----------------------------------------------------------------


def notes_search(
    cfg: NotesConfig,
    query: str,
    subdir: str | None = None,
) -> dict[str, Any]:
    if not query or not query.strip():
        raise ValueError("query vuota")
    root = _vault_root(cfg)
    base = resolve_within(cfg.root, subdir or ".")
    needle = query.lower()

    matches: list[str] = []
    truncated = False
    for p in sorted(_iter_vault_files(root, base, "*.md")):
        if p.is_symlink():
            continue  # un symlink può uscire dal vault: mai leggerne il contenuto
        rel = p.relative_to(root)
        text = p.read_text(encoding="utf-8", errors="replace")
        for lineno, line in enumerate(text.splitlines(), start=1):
            if needle in line.lower():
                if len(matches) >= MAX_SEARCH_LINES:
                    truncated = True
                    break
                matches.append(f"{rel}:{lineno}:{line}")
        if truncated:
            break
    return {"query": query, "matches": matches, "truncated": truncated}


# --- notes_write ----------------------------------------------------------------


def notes_write(
    cfg: NotesConfig,
    path: str,
    content: str,
    *,
    mode: str = "create",
) -> dict[str, Any]:
    if mode not in _VALID_WRITE_MODES:
        raise ValueError(f"mode '{mode}' non valido: usare {sorted(_VALID_WRITE_MODES)}")
    target, rel = _resolve_md(cfg, path)
    if not rel.parts or rel.parts[0] not in cfg.write_dirs or len(rel.parts) < 2:
        raise WriteNotAllowedError(
            f"scrittura consentita solo sotto: {', '.join(cfg.write_dirs)} (richiesto: '{rel}')"
        )

    # Mai scrivere su un tree in conflitto; pull PRIMA di toccare il filesystem.
    _ensure_tree_not_conflicted(cfg)
    _pull_rebase(cfg)

    if mode == "create" and target.exists():
        raise NotesFileError(f"'{rel}' esiste già (mode=create)")

    target.parent.mkdir(parents=True, exist_ok=True)
    if mode == "append":
        with target.open("a", encoding="utf-8") as f:
            f.write(content)
    else:
        target.write_text(content, encoding="utf-8")

    _run_git(cfg, ["add", "--", str(rel)])
    _run_git(cfg, ["commit", "-m", f"notes(mcp): {mode} {rel}", "--", str(rel)])
    sha = _head_sha(cfg)

    branch = _current_branch(cfg)
    push = _run_git(cfg, ["push", "origin", f"HEAD:{branch}"], check=False)
    if push.returncode != 0:
        head = (push.stderr or "").strip().splitlines()
        first = head[0] if head else ""
        raise NotesSyncError(f"push fallito (commit locale {sha[:8]} preservato): {first[:300]}")

    return {"path": str(rel), "mode": mode, "commit": sha, "pushed": True}


# --- notes_sync_pull -------------------------------------------------------------


def notes_sync_pull(cfg: NotesConfig) -> dict[str, Any]:
    before = _head_sha(cfg)
    _pull_rebase(cfg)
    after = _head_sha(cfg)
    return {"updated": after != before, "head": after}


# --- notes_sync_status -----------------------------------------------------------


def notes_sync_status(cfg: NotesConfig) -> dict[str, Any]:
    # Fetch best-effort: ahead/behind aggiornati anche se origin è offline.
    _run_git(cfg, ["fetch", "--quiet"], check=False)
    proc = _run_git(cfg, ["status", "--porcelain=v1", "--branch", "-z"])
    return _parse_porcelain_v1(proc.stdout)


__all__ = [
    "DEFAULT_MAX_READ_BYTES",
    "GIT_TIMEOUT_SECONDS",
    "MAX_LIST_ENTRIES",
    "MAX_SEARCH_LINES",
    "FileTooLargeError",
    "GitNotFoundError",
    "NotesConfig",
    "NotesFileError",
    "NotesSyncError",
    "WriteNotAllowedError",
    "notes_list",
    "notes_read",
    "notes_search",
    "notes_sync_pull",
    "notes_sync_status",
    "notes_write",
]
