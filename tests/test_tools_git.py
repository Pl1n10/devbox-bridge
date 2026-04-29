"""Test tool git — read e write su repo git temporaneo."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from devbox_bridge.config import AppConfig
from devbox_bridge.security.paths import PathSecurityError
from devbox_bridge.tools.filesystem import WriteNotAllowedError
from devbox_bridge.tools.git import (
    BranchNameError,
    CommitMessageError,
    CommitPathsError,
    GitCommandError,
    NotARepositoryError,
    PushNotAllowedError,
    RemoteNameError,
    git_branch_current,
    git_commit,
    git_create_branch,
    git_diff,
    git_log,
    git_push,
    git_status,
)


def _git(repo: Path, *cmd: str) -> str:
    proc = subprocess.run(
        ["git", *cmd],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    )
    return proc.stdout


# --- git_status -------------------------------------------------------------


def test_git_status_clean(config_git_ro: AppConfig, tmp_git_repo: Path) -> None:
    out = git_status(config_git_ro, "gitproj")
    assert out["branch"] == "main"
    assert out["detached"] is False
    assert out["upstream"] is None
    assert out["clean"] is True
    assert out["staged"] == []
    assert out["unstaged"] == []
    assert out["untracked"] == []


def test_git_status_with_unstaged_modification(
    config_git_rw: AppConfig, tmp_git_repo: Path
) -> None:
    (tmp_git_repo / "README.md").write_text("# changed\n", encoding="utf-8")
    out = git_status(config_git_rw, "gitproj")
    assert out["clean"] is False
    assert out["staged"] == []
    assert {e["path"] for e in out["unstaged"]} == {"README.md"}
    assert out["unstaged"][0]["code"] == "M"


def test_git_status_with_staged_and_unstaged(
    config_git_rw: AppConfig, tmp_git_repo: Path
) -> None:
    (tmp_git_repo / "README.md").write_text("# v2\n", encoding="utf-8")
    _git(tmp_git_repo, "add", "README.md")
    (tmp_git_repo / "README.md").write_text("# v3\n", encoding="utf-8")

    out = git_status(config_git_rw, "gitproj")
    assert {e["path"] for e in out["staged"]} == {"README.md"}
    assert out["staged"][0]["code"] == "M"
    assert {e["path"] for e in out["unstaged"]} == {"README.md"}
    assert out["unstaged"][0]["code"] == "M"


def test_git_status_with_untracked(
    config_git_rw: AppConfig, tmp_git_repo: Path
) -> None:
    (tmp_git_repo / "newfile.txt").write_text("hi\n", encoding="utf-8")
    out = git_status(config_git_rw, "gitproj")
    assert out["untracked"] == ["newfile.txt"]


def test_git_status_not_a_repository(
    tmp_path: Path,
    tmp_token_file: Path,
    config_factory,
) -> None:
    plain = tmp_path / "plain"
    plain.mkdir()
    (plain / "README.md").write_text("hi\n", encoding="utf-8")
    cfg = config_factory(plain, project_name="plain", write_enabled=False)
    with pytest.raises(NotARepositoryError):
        git_status(cfg, "plain")


# --- git_diff ---------------------------------------------------------------


def test_git_diff_unstaged(
    config_git_rw: AppConfig, tmp_git_repo: Path
) -> None:
    (tmp_git_repo / "README.md").write_text("# changed\n", encoding="utf-8")
    out = git_diff(config_git_rw, "gitproj")
    assert out["staged"] is False
    assert "diff --git" in out["diff"]
    assert "+# changed" in out["diff"]
    assert out["truncated"] is False


def test_git_diff_staged(
    config_git_rw: AppConfig, tmp_git_repo: Path
) -> None:
    (tmp_git_repo / "README.md").write_text("# v2\n", encoding="utf-8")
    _git(tmp_git_repo, "add", "README.md")
    # Non staged: la modifica è già passata in staging.
    out_unstaged = git_diff(config_git_rw, "gitproj")
    assert out_unstaged["diff"] == ""
    out_staged = git_diff(config_git_rw, "gitproj", staged=True)
    assert "+# v2" in out_staged["diff"]


def test_git_diff_path_filter(
    config_git_rw: AppConfig, tmp_git_repo: Path
) -> None:
    (tmp_git_repo / "README.md").write_text("# changed\n", encoding="utf-8")
    (tmp_git_repo / "src" / "main.py").write_text(
        "def main(): pass\n", encoding="utf-8"
    )
    out = git_diff(config_git_rw, "gitproj", path="README.md")
    assert "README.md" in out["diff"]
    assert "main.py" not in out["diff"]


def test_git_diff_path_traversal_refused(
    config_git_rw: AppConfig, tmp_git_repo: Path
) -> None:
    with pytest.raises(PathSecurityError):
        git_diff(config_git_rw, "gitproj", path="../escape")


# --- git_log ----------------------------------------------------------------


def test_git_log_default(
    config_git_ro: AppConfig, tmp_git_repo: Path
) -> None:
    out = git_log(config_git_ro, "gitproj")
    assert out["limit"] == 20
    assert len(out["commits"]) == 2
    subjects = [c["subject"] for c in out["commits"]]
    assert subjects == ["add main", "initial commit"]
    first = out["commits"][0]
    assert first["author_name"] == "Test"
    assert first["author_email"] == "test@example.com"
    assert len(first["hash"]) == 40
    assert len(first["short_hash"]) >= 7


def test_git_log_custom_limit(
    config_git_ro: AppConfig, tmp_git_repo: Path
) -> None:
    out = git_log(config_git_ro, "gitproj", limit=1)
    assert out["limit"] == 1
    assert len(out["commits"]) == 1


def test_git_log_limit_clamp_to_max(
    config_git_ro: AppConfig, tmp_git_repo: Path
) -> None:
    out = git_log(config_git_ro, "gitproj", limit=10_000)
    assert out["limit"] == 200  # MAX_LOG_LIMIT


def test_git_log_limit_must_be_positive(
    config_git_ro: AppConfig,
) -> None:
    with pytest.raises(ValueError):
        git_log(config_git_ro, "gitproj", limit=0)


def test_git_log_repo_without_commits(
    tmp_path: Path, tmp_token_file: Path, config_factory
) -> None:
    repo = tmp_path / "empty"
    repo.mkdir()
    subprocess.run(
        ["git", "init", "-b", "main"],
        cwd=repo,
        check=True,
        capture_output=True,
    )
    cfg = config_factory(repo, project_name="empty")
    out = git_log(cfg, "empty")
    assert out["commits"] == []


# --- git_branch_current -----------------------------------------------------


def test_git_branch_current(
    config_git_ro: AppConfig, tmp_git_repo: Path
) -> None:
    out = git_branch_current(config_git_ro, "gitproj")
    assert out == {"branch": "main", "detached": False, "head": None}


def test_git_branch_current_detached(
    config_git_rw: AppConfig, tmp_git_repo: Path
) -> None:
    sha = _git(tmp_git_repo, "rev-parse", "HEAD").strip()
    _git(tmp_git_repo, "checkout", "--detach", sha)
    out = git_branch_current(config_git_rw, "gitproj")
    assert out["branch"] is None
    assert out["detached"] is True
    assert out["head"] == sha


# --- git_create_branch ------------------------------------------------------


def test_git_create_branch_success(
    config_git_rw: AppConfig, tmp_git_repo: Path
) -> None:
    out = git_create_branch(config_git_rw, "gitproj", "feature/foo")
    assert out["branch"] == "feature/foo"
    assert len(out["from"]) == 40
    branch = git_branch_current(config_git_rw, "gitproj")["branch"]
    assert branch == "feature/foo"


def test_git_create_branch_invalid_name(
    config_git_rw: AppConfig, tmp_git_repo: Path
) -> None:
    with pytest.raises(BranchNameError):
        git_create_branch(config_git_rw, "gitproj", "..bad")


def test_git_create_branch_with_newline_refused(
    config_git_rw: AppConfig, tmp_git_repo: Path
) -> None:
    with pytest.raises(BranchNameError):
        git_create_branch(config_git_rw, "gitproj", "ok\nbad")


def test_git_create_branch_already_exists(
    config_git_rw: AppConfig, tmp_git_repo: Path
) -> None:
    git_create_branch(config_git_rw, "gitproj", "feature/foo")
    _git(tmp_git_repo, "checkout", "main")
    with pytest.raises(GitCommandError):
        git_create_branch(config_git_rw, "gitproj", "feature/foo")


def test_git_create_branch_requires_write_enabled(
    config_git_ro: AppConfig, tmp_git_repo: Path
) -> None:
    with pytest.raises(WriteNotAllowedError):
        git_create_branch(config_git_ro, "gitproj", "feature/foo")


# --- git_commit -------------------------------------------------------------


def test_git_commit_success(
    config_git_rw: AppConfig, tmp_git_repo: Path
) -> None:
    (tmp_git_repo / "README.md").write_text("# v2\n", encoding="utf-8")
    out = git_commit(
        config_git_rw, "gitproj", "update README", paths=["README.md"]
    )
    assert len(out["hash"]) == 40
    assert out["branch"] == "main"
    assert out["paths"] == ["README.md"]


def test_git_commit_paths_required(
    config_git_rw: AppConfig, tmp_git_repo: Path
) -> None:
    (tmp_git_repo / "README.md").write_text("# v2\n", encoding="utf-8")
    with pytest.raises(CommitPathsError):
        git_commit(config_git_rw, "gitproj", "msg", paths=[])


def test_git_commit_message_required(
    config_git_rw: AppConfig, tmp_git_repo: Path
) -> None:
    (tmp_git_repo / "README.md").write_text("# v2\n", encoding="utf-8")
    with pytest.raises(CommitMessageError):
        git_commit(config_git_rw, "gitproj", "   ", paths=["README.md"])


def test_git_commit_path_outside_project_refused(
    config_git_rw: AppConfig, tmp_git_repo: Path
) -> None:
    with pytest.raises(PathSecurityError):
        git_commit(
            config_git_rw,
            "gitproj",
            "msg",
            paths=["../outside"],
        )


def test_git_commit_no_changes_fails(
    config_git_rw: AppConfig, tmp_git_repo: Path
) -> None:
    with pytest.raises(GitCommandError):
        git_commit(
            config_git_rw, "gitproj", "noop", paths=["README.md"]
        )


def test_git_commit_requires_write_enabled(
    config_git_ro: AppConfig, tmp_git_repo: Path
) -> None:
    (tmp_git_repo / "README.md").write_text("# v2\n", encoding="utf-8")
    with pytest.raises(WriteNotAllowedError):
        git_commit(
            config_git_ro, "gitproj", "msg", paths=["README.md"]
        )


def test_git_commit_only_commits_listed_paths(
    config_git_rw: AppConfig, tmp_git_repo: Path
) -> None:
    """Garantisce assenza di `git commit -a` implicito."""
    (tmp_git_repo / "README.md").write_text("# v2\n", encoding="utf-8")
    (tmp_git_repo / "src" / "main.py").write_text(
        "def main(): return 1\n", encoding="utf-8"
    )
    out = git_commit(
        config_git_rw, "gitproj", "only README", paths=["README.md"]
    )
    # main.py rimane modificato non committato.
    status = git_status(config_git_rw, "gitproj")
    assert {e["path"] for e in status["unstaged"]} == {"src/main.py"}
    assert out["paths"] == ["README.md"]


# --- git_push ---------------------------------------------------------------


def test_git_push_requires_allow_push(
    config_git_rw: AppConfig, tmp_git_repo: Path
) -> None:
    with pytest.raises(PushNotAllowedError):
        git_push(config_git_rw, "gitproj")


def test_git_push_requires_write_enabled(
    config_git_ro: AppConfig, tmp_git_repo: Path
) -> None:
    with pytest.raises(WriteNotAllowedError):
        git_push(config_git_ro, "gitproj")


def test_git_push_invalid_remote_name(
    config_git_push: AppConfig,
) -> None:
    with pytest.raises(RemoteNameError):
        git_push(config_git_push, "gitproj", remote="bad name")


def test_git_push_success_to_local_bare_remote(
    config_git_push: AppConfig,
    tmp_git_repo_with_origin: tuple[Path, Path],
) -> None:
    repo, bare = tmp_git_repo_with_origin
    out = git_push(config_git_push, "gitproj")
    assert out["remote"] == "origin"
    assert out["branch"] == "main"
    # Il bare ora ha lo stesso HEAD del repo locale.
    repo_head = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=repo, check=True,
        capture_output=True, text=True,
    ).stdout.strip()
    bare_head = subprocess.run(
        ["git", "rev-parse", "main"], cwd=bare, check=True,
        capture_output=True, text=True,
    ).stdout.strip()
    assert repo_head == bare_head
