"""Tool MCP — git.

Tool implementati nello step 8.

Read (audit-on-demand, default audit_reads=false):
  - git_status         → porcelain v1 + branch info (ahead/behind/upstream).
  - git_diff           → unified diff testuale (staged|unstaged, opzionale path).
  - git_log            → ultimi N commit (struttura JSON).
  - git_branch_current → branch corrente o (detached, head sha).

Write (richiede project.write_enabled, audit obbligatorio nel server):
  - git_create_branch → crea branch + checkout (no force, no -D).
  - git_commit        → commit con paths obbligatori (mai `git commit -a`).
  - git_push          → push (richiede project.allow_push); no --force/--mirror/--delete.

Esplicitamente NON implementato: reset --hard, push --force, clean, branch -D.
Vedi `docs/devbox-bridge-brief.md:55`.

Invarianti:
  - subprocess.run con lista args, mai shell=True.
  - cwd forzato a project root.
  - env sanitizzato via security.env.sanitize_env() (no LD_PRELOAD, niente
    secret leak; env_passthrough rispettato).
  - --no-pager su tutti i comandi.
  - timeout obbligatorio (GIT_TIMEOUT_SECONDS).
  - paths in git_commit / path-filter in git_diff validati con resolve_within.
  - branch name validato con `git check-ref-format --branch`.
  - remote validato con regex stretta.

Mapping eccezioni → server outcome:
  WriteNotAllowedError, PushNotAllowedError → "denied"
  PathSecurityError                          → "denied" (event "path.rejected")
  BranchNameError, RemoteNameError, ...      → "error"
  GitCommandError, NotARepositoryError       → "error"
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

from devbox_bridge.config import AppConfig, ProjectConfig
from devbox_bridge.security.env import get_current_env, sanitize_env
from devbox_bridge.security.paths import resolve_within
from devbox_bridge.tools.filesystem import WriteNotAllowedError

GIT_TIMEOUT_SECONDS: int = 30
DEFAULT_LOG_LIMIT: int = 20
MAX_LOG_LIMIT: int = 200
MAX_DIFF_BYTES: int = 2 * 1024 * 1024  # 2 MB
MAX_PUSH_OUTPUT_BYTES: int = 64 * 1024  # 64 KB

# Remote: stesso pattern accettato di fatto da git (alfanumerico + . _ -).
_REMOTE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")

# Backstop su push: se un argomento atteso comparisse, abortire. Il signature
# attuale non consente di passarli, ma teniamo la validazione come strato
# difensivo se la firma evolvesse.
_FORBIDDEN_PUSH_FLAGS: frozenset[str] = frozenset(
    {
        "--force",
        "-f",
        "--mirror",
        "--delete",
        "-d",
        "--all",
        "--prune",
        "--force-with-lease",
    }
)


# --- Eccezioni ---------------------------------------------------------------


class GitNotFoundError(RuntimeError):
    """`git` non trovato nel PATH."""


class GitCommandError(RuntimeError):
    """Un comando git è uscito con exit code != 0 (errore inatteso)."""

    def __init__(self, args: list[str], exit_code: int, stderr: str) -> None:
        excerpt = (stderr or "").strip().splitlines()
        head = excerpt[0] if excerpt else ""
        cmd = " ".join(args[1:]) if len(args) > 1 else ""
        super().__init__(f"git {cmd} → exit {exit_code}: {head[:300]}")
        self.cmd_args: list[str] = list(args)
        self.exit_code = exit_code
        self.stderr = stderr


class NotARepositoryError(GitCommandError):
    """La project root non è un repo git."""


class BranchNameError(ValueError):
    """Nome branch non valido per `git check-ref-format --branch`."""


class RemoteNameError(ValueError):
    """Nome remote non valido."""


class CommitPathsError(ValueError):
    """`git_commit` invocato senza paths o con paths invalidi."""


class CommitMessageError(ValueError):
    """Messaggio di commit vuoto."""


class PushNotAllowedError(PermissionError):
    """`git_push` invocato su progetto con allow_push=False."""


# --- Helper privati ----------------------------------------------------------


def _project(cfg: AppConfig, project: str) -> ProjectConfig:
    return cfg.project(project)


def _project_root(proj: ProjectConfig) -> Path:
    return proj.path.resolve(strict=True)


def _git_executable() -> str:
    p = shutil.which("git")
    if p is None:
        raise GitNotFoundError(
            "git non trovato nel PATH; installa con `apt install git`"
        )
    return p


def _build_env(proj: ProjectConfig) -> dict[str, str]:
    env = sanitize_env(get_current_env(), passthrough=proj.env_passthrough)
    # No prompt interattivi (TTY/SSH/HTTP), no lock opportunistici.
    env.setdefault("GIT_TERMINAL_PROMPT", "0")
    env.setdefault("GIT_OPTIONAL_LOCKS", "0")
    return env


def _run_git(
    proj: ProjectConfig,
    args: list[str],
    *,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    git = _git_executable()
    full = [git, "--no-pager", *args]
    try:
        proc = subprocess.run(  # noqa: S603 — git path da shutil.which, args lista
            full,
            cwd=str(_project_root(proj)),
            capture_output=True,
            text=True,
            timeout=GIT_TIMEOUT_SECONDS,
            check=False,
            env=_build_env(proj),
        )
    except subprocess.TimeoutExpired as e:
        raise GitCommandError(
            args=full, exit_code=-1, stderr=f"timeout dopo {GIT_TIMEOUT_SECONDS}s"
        ) from e

    if check and proc.returncode != 0:
        if "not a git repository" in proc.stderr.lower():
            raise NotARepositoryError(
                args=full, exit_code=proc.returncode, stderr=proc.stderr
            )
        raise GitCommandError(
            args=full, exit_code=proc.returncode, stderr=proc.stderr
        )
    return proc


def _ensure_writable(proj: ProjectConfig, project_name: str) -> None:
    if not proj.write_enabled:
        raise WriteNotAllowedError(
            f"project '{project_name}' ha write_enabled=False"
        )


def _validate_branch_name(proj: ProjectConfig, name: str) -> None:
    if not name or "\n" in name or "\0" in name:
        raise BranchNameError(f"nome branch '{name}' non valido")
    proc = _run_git(
        proj, ["check-ref-format", "--branch", name], check=False
    )
    if proc.returncode != 0:
        raise BranchNameError(
            f"nome branch '{name}' non valido (git check-ref-format)"
        )


def _validate_remote_name(name: str) -> None:
    if not _REMOTE_NAME_RE.fullmatch(name):
        raise RemoteNameError(f"nome remote '{name}' non valido")


def _truncate(text: str, max_bytes: int) -> tuple[str, bool, int]:
    data = text.encode("utf-8", errors="replace")
    total = len(data)
    if total <= max_bytes:
        return text, False, total
    truncated = data[:max_bytes].decode("utf-8", errors="replace")
    return truncated, True, total


# --- git_status --------------------------------------------------------------


_AHEAD_RE = re.compile(r"ahead\s+(\d+)")
_BEHIND_RE = re.compile(r"behind\s+(\d+)")


def _parse_branch_header(
    header: str,
) -> tuple[str | None, str | None, int, int, bool]:
    """Parse la prima entry porcelain dopo `## ` (header già strippato).

    Esempi gestiti:
      - `main`
      - `release/1.0.x`
      - `main...origin/main`
      - `main...origin/main [ahead 1, behind 2]`
      - `HEAD (no branch)` → detached
      - `No commits yet on main` → repo nuovo, no commit
    """
    if header.startswith("HEAD (no branch)"):
        return None, None, 0, 0, True
    if header.startswith("No commits yet on "):
        new_local: str = header[len("No commits yet on "):].strip()
        return new_local or None, None, 0, 0, False

    rest = header
    bracket = ""
    if "[" in rest and rest.endswith("]"):
        rest, bracket = rest.rsplit("[", 1)
        rest = rest.strip()
        bracket = bracket.rstrip("]")

    local: str | None
    upstream: str | None
    if "..." in rest:
        local_str, upstream_str = rest.split("...", 1)
        local = local_str.strip() or None
        upstream = upstream_str.strip() or None
    else:
        local = rest.strip() or None
        upstream = None

    ahead_m = _AHEAD_RE.search(bracket)
    behind_m = _BEHIND_RE.search(bracket)
    ahead = int(ahead_m.group(1)) if ahead_m else 0
    behind = int(behind_m.group(1)) if behind_m else 0
    return local, upstream, ahead, behind, False


def _parse_porcelain_v1(output: str) -> dict[str, Any]:
    """Parsing porcelain v1 con `-z`. Header `## ...` NUL-terminato come ogni
    entry; le entry XY hanno path che continua fino al NUL successivo. Per
    rename/copy (X o Y in {R, C}) la entry SUCCESSIVA è il path originale.
    """
    branch: str | None = None
    upstream: str | None = None
    ahead = 0
    behind = 0
    detached = False

    raw = output
    if raw.startswith("## "):
        nul_idx = raw.find("\0")
        header = raw[3:nul_idx] if nul_idx != -1 else raw[3:]
        raw = raw[nul_idx + 1:] if nul_idx != -1 else ""
        branch, upstream, ahead, behind, detached = _parse_branch_header(header)

    staged: list[dict[str, Any]] = []
    unstaged: list[dict[str, Any]] = []
    untracked: list[str] = []

    entries = [e for e in raw.split("\0") if e != ""]
    i = 0
    while i < len(entries):
        entry = entries[i]
        if len(entry) < 3:
            i += 1
            continue
        x, y, path = entry[0], entry[1], entry[3:]

        if x == "?" and y == "?":
            untracked.append(path)
            i += 1
            continue

        orig: str | None = None
        if x in ("R", "C") or y in ("R", "C"):
            if i + 1 < len(entries):
                orig = entries[i + 1]
                i += 1

        if x not in (" ", "?"):
            entry_dict: dict[str, Any] = {"code": x, "path": path}
            if orig is not None:
                entry_dict["orig"] = orig
            staged.append(entry_dict)
        if y not in (" ", "?"):
            unstaged.append({"code": y, "path": path})
        i += 1

    return {
        "branch": branch,
        "detached": detached,
        "upstream": upstream,
        "ahead": ahead,
        "behind": behind,
        "staged": staged,
        "unstaged": unstaged,
        "untracked": untracked,
        "clean": not staged and not unstaged and not untracked,
    }


def git_status(cfg: AppConfig, project: str) -> dict[str, Any]:
    proj = _project(cfg, project)
    proc = _run_git(proj, ["status", "--porcelain=v1", "--branch", "-z"])
    return _parse_porcelain_v1(proc.stdout)


# --- git_diff ----------------------------------------------------------------


def git_diff(
    cfg: AppConfig,
    project: str,
    *,
    staged: bool = False,
    path: str | None = None,
) -> dict[str, Any]:
    proj = _project(cfg, project)
    args: list[str] = ["diff", "--no-color"]
    if staged:
        args.append("--cached")
    if path is not None:
        target = resolve_within(proj.path, path)
        rel = target.relative_to(_project_root(proj))
        args += ["--", str(rel)]
    proc = _run_git(proj, args)
    diff, truncated, total_bytes = _truncate(proc.stdout, MAX_DIFF_BYTES)
    return {
        "staged": staged,
        "path": path,
        "diff": diff,
        "bytes": total_bytes,
        "truncated": truncated,
    }


# --- git_log -----------------------------------------------------------------


# Field separator (US, 0x1f) e record separator (RS, 0x1e). Entrambi non
# stampabili → improbabile collisione con contenuto di commit messages.
_LOG_FS = "\x1f"
_LOG_RS = "\x1e"
_LOG_FORMAT = (
    f"%H{_LOG_FS}%h{_LOG_FS}%aN{_LOG_FS}%aE{_LOG_FS}%aI{_LOG_FS}%s{_LOG_RS}"
)


def git_log(
    cfg: AppConfig,
    project: str,
    *,
    limit: int = DEFAULT_LOG_LIMIT,
) -> dict[str, Any]:
    if limit < 1:
        raise ValueError("limit deve essere >= 1")
    effective = min(limit, MAX_LOG_LIMIT)
    proj = _project(cfg, project)
    args = [
        "log",
        f"-n{effective}",
        f"--pretty=format:{_LOG_FORMAT}",
    ]
    try:
        proc = _run_git(proj, args)
    except GitCommandError as e:
        if "does not have any commits yet" in (e.stderr or "").lower():
            return {"limit": effective, "commits": []}
        raise

    commits: list[dict[str, str]] = []
    for record in proc.stdout.split(_LOG_RS):
        record = record.strip("\n")
        if not record:
            continue
        parts = record.split(_LOG_FS)
        if len(parts) < 6:
            continue
        full, short, name, email, date, subject = parts[:6]
        commits.append(
            {
                "hash": full,
                "short_hash": short,
                "author_name": name,
                "author_email": email,
                "date": date,
                "subject": subject,
            }
        )

    return {"limit": effective, "commits": commits}


# --- git_branch_current ------------------------------------------------------


def git_branch_current(cfg: AppConfig, project: str) -> dict[str, Any]:
    proj = _project(cfg, project)
    proc = _run_git(
        proj, ["symbolic-ref", "--short", "-q", "HEAD"], check=False
    )
    if proc.returncode == 0:
        return {
            "branch": proc.stdout.strip(),
            "detached": False,
            "head": None,
        }
    sha = _run_git(proj, ["rev-parse", "HEAD"]).stdout.strip()
    return {"branch": None, "detached": True, "head": sha}


# --- git_create_branch -------------------------------------------------------


def git_create_branch(
    cfg: AppConfig, project: str, name: str
) -> dict[str, Any]:
    proj = _project(cfg, project)
    _ensure_writable(proj, project)
    _validate_branch_name(proj, name)

    proc_exists = _run_git(
        proj,
        ["rev-parse", "--verify", "--quiet", f"refs/heads/{name}"],
        check=False,
    )
    if proc_exists.returncode == 0:
        raise GitCommandError(
            args=["git", "branch", name],
            exit_code=128,
            stderr=f"branch '{name}' esiste già",
        )

    head_before = _run_git(proj, ["rev-parse", "HEAD"]).stdout.strip()
    _run_git(proj, ["checkout", "-b", name])
    return {"branch": name, "from": head_before}


# --- git_commit --------------------------------------------------------------


def git_commit(
    cfg: AppConfig,
    project: str,
    message: str,
    paths: list[str],
) -> dict[str, Any]:
    proj = _project(cfg, project)
    _ensure_writable(proj, project)

    if not isinstance(message, str) or not message.strip():
        raise CommitMessageError("messaggio di commit vuoto")
    if not paths:
        raise CommitPathsError(
            "paths obbligatorio: niente `git commit -a` implicito"
        )

    root = _project_root(proj)
    rel_paths: list[str] = []
    for p in paths:
        target = resolve_within(proj.path, p)
        rel_paths.append(str(target.relative_to(root)))

    _run_git(proj, ["add", "--", *rel_paths])

    proc = _run_git(
        proj,
        ["commit", "-m", message, "--", *rel_paths],
        check=False,
    )
    if proc.returncode != 0:
        raise GitCommandError(
            args=["git", "commit", "-m", "<msg>", "--", *rel_paths],
            exit_code=proc.returncode,
            stderr=proc.stderr or proc.stdout,
        )

    sha = _run_git(proj, ["rev-parse", "HEAD"]).stdout.strip()
    short = _run_git(proj, ["rev-parse", "--short", "HEAD"]).stdout.strip()
    branch_info = git_branch_current(cfg, project)
    return {
        "hash": sha,
        "short_hash": short,
        "branch": branch_info.get("branch"),
        "paths": rel_paths,
    }


# --- git_push ----------------------------------------------------------------


def git_push(
    cfg: AppConfig,
    project: str,
    *,
    remote: str = "origin",
) -> dict[str, Any]:
    proj = _project(cfg, project)
    _ensure_writable(proj, project)
    if not proj.allow_push:
        raise PushNotAllowedError(
            f"project '{project}' ha allow_push=False"
        )
    _validate_remote_name(remote)

    branch_info = git_branch_current(cfg, project)
    branch = branch_info.get("branch")
    if not branch:
        raise GitCommandError(
            args=["git", "push", remote, "HEAD"],
            exit_code=128,
            stderr="HEAD detached: rifiuto push senza branch corrente",
        )

    args = ["push", remote, f"HEAD:{branch}"]
    for tok in args:
        if tok in _FORBIDDEN_PUSH_FLAGS:
            raise GitCommandError(
                args=["git", *args],
                exit_code=-1,
                stderr=f"argomento push non consentito: '{tok}'",
            )

    proc = _run_git(proj, args, check=False)
    stdout, stdout_truncated, _ = _truncate(proc.stdout, MAX_PUSH_OUTPUT_BYTES)
    stderr, stderr_truncated, _ = _truncate(proc.stderr, MAX_PUSH_OUTPUT_BYTES)

    if proc.returncode != 0:
        raise GitCommandError(
            args=["git", *args],
            exit_code=proc.returncode,
            stderr=stderr,
        )

    return {
        "remote": remote,
        "branch": branch,
        "stdout": stdout,
        "stderr": stderr,
        "stdout_truncated": stdout_truncated,
        "stderr_truncated": stderr_truncated,
    }


__all__ = [
    "DEFAULT_LOG_LIMIT",
    "MAX_DIFF_BYTES",
    "MAX_LOG_LIMIT",
    "BranchNameError",
    "CommitMessageError",
    "CommitPathsError",
    "GitCommandError",
    "GitNotFoundError",
    "NotARepositoryError",
    "PushNotAllowedError",
    "RemoteNameError",
    "WriteNotAllowedError",
    "git_branch_current",
    "git_commit",
    "git_create_branch",
    "git_diff",
    "git_log",
    "git_push",
    "git_status",
]
