"""Test tools/notes.py — step 13 (vault Mnemosyne).

Spec: mnemosyne/notes-module/SPEC-step13-notes.md. Vincoli da ADR-008/009:
containment nel NOTES_ROOT, write whitelist (llm/, inbox/), pull prima di
ogni write, commit atomici, mai --force, nessuna delete.

Infrastruttura: repo git temporaneo con bare origin locale — nessun test
tocca il vero ~/notes/.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from devbox_bridge.security.paths import PathSecurityError
from devbox_bridge.tools import notes
from devbox_bridge.tools.filesystem import FileTooLargeError, WriteNotAllowedError
from devbox_bridge.tools.notes import (
    NotesConfig,
    NotesFileError,
    NotesSyncError,
)

# --- Fixtures -----------------------------------------------------------------


def _run(cwd: Path, *cmd: str) -> str:
    proc = subprocess.run(
        list(cmd), cwd=cwd, check=True, capture_output=True, text=True
    )
    return proc.stdout


@pytest.fixture
def vault(tmp_path: Path) -> tuple[Path, Path]:
    """Vault di test: working copy + bare origin, struttura minima del vault
    reale (llm/, inbox/, ops/, work/), primo commit pushato su main."""
    bare = tmp_path / "origin.git"
    subprocess.run(
        ["git", "init", "--bare", "-b", "main", str(bare)],
        check=True,
        capture_output=True,
    )

    root = tmp_path / "notes"
    for sub in ("llm", "inbox", "ops", "work"):
        (root / sub).mkdir(parents=True)
        (root / sub / "INDEX.md").write_text(f"# {sub}\n", encoding="utf-8")
    (root / "INDEX.md").write_text("# vault\n", encoding="utf-8")
    (root / "work" / "note1.md").write_text(
        "# Nota\n\nHello WORLD di prova.\n", encoding="utf-8"
    )

    _run(root, "git", "init", "-b", "main")
    _run(root, "git", "config", "user.email", "test@example.com")
    _run(root, "git", "config", "user.name", "Test")
    _run(root, "git", "config", "commit.gpgsign", "false")
    _run(root, "git", "remote", "add", "origin", str(bare))
    _run(root, "git", "add", "-A")
    _run(root, "git", "commit", "-m", "initial vault")
    _run(root, "git", "push", "-u", "origin", "main")
    return root, bare


@pytest.fixture
def cfg(vault: tuple[Path, Path]) -> NotesConfig:
    root, _ = vault
    return NotesConfig(root=root)


@pytest.fixture
def second_clone(vault: tuple[Path, Path], tmp_path: Path) -> Path:
    """Secondo working clone (simula il PC di Roberto)."""
    root, bare = vault
    clone = tmp_path / "clone2"
    subprocess.run(
        ["git", "clone", str(bare), str(clone)],
        check=True,
        capture_output=True,
    )
    _run(clone, "git", "config", "user.email", "pc@example.com")
    _run(clone, "git", "config", "user.name", "PC")
    _run(clone, "git", "config", "commit.gpgsign", "false")
    return clone


@pytest.fixture
def git_recorder(monkeypatch: pytest.MonkeyPatch) -> list[list[str]]:
    """Registra gli argv di ogni subprocess.run lanciato dal modulo notes."""
    recorded: list[list[str]] = []
    real_run = subprocess.run

    def recording_run(args, **kwargs):  # type: ignore[no-untyped-def]
        if isinstance(args, list):
            recorded.append([str(a) for a in args])
        return real_run(args, **kwargs)

    monkeypatch.setattr(notes.subprocess, "run", recording_run)
    return recorded


def _last_commit_subject(root: Path) -> str:
    return _run(root, "git", "log", "-1", "--pretty=%s").strip()


def _commit_count(root: Path) -> int:
    return int(_run(root, "git", "rev-list", "--count", "HEAD").strip())


def _bare_has_file(bare: Path, rel: str) -> bool:
    proc = subprocess.run(
        ["git", "ls-tree", "-r", "--name-only", "main"],
        cwd=bare,
        check=True,
        capture_output=True,
        text=True,
    )
    return rel in proc.stdout.splitlines()


# --- Config -------------------------------------------------------------------


class TestNotesConfig:
    def test_defaults(self, tmp_path: Path) -> None:
        c = NotesConfig(root=tmp_path)
        assert c.write_dirs == ("llm", "inbox")
        assert c.max_read_bytes == 1_048_576

    def test_from_env_overrides(self, tmp_path: Path) -> None:
        env = {
            "NOTES_ROOT": str(tmp_path),
            "NOTES_WRITE_DIRS": "llm, inbox ,drafts",
            "NOTES_MAX_READ_BYTES": "2048",
        }
        c = NotesConfig.from_env(env)
        assert c.root == tmp_path
        assert c.write_dirs == ("llm", "inbox", "drafts")
        assert c.max_read_bytes == 2048

    def test_from_env_defaults(self) -> None:
        c = NotesConfig.from_env({})
        assert c.root == Path("~/notes").expanduser()
        assert c.write_dirs == ("llm", "inbox")

    def test_write_dirs_traversal_rejected(self, tmp_path: Path) -> None:
        with pytest.raises(ValueError):
            NotesConfig(root=tmp_path, write_dirs=("../evil",))
        with pytest.raises(ValueError):
            NotesConfig(root=tmp_path, write_dirs=("/abs",))


# --- Containment & whitelist ---------------------------------------------------


class TestContainment:
    def test_read_outside_root_rejected(self, cfg: NotesConfig, tmp_path: Path) -> None:
        with pytest.raises(PathSecurityError):
            notes.notes_read(cfg, "../outside.md")
        with pytest.raises(PathSecurityError):
            notes.notes_read(cfg, "/etc/passwd")

        # Symlink che esce dal root
        outside = tmp_path / "outside.md"
        outside.write_text("secret\n", encoding="utf-8")
        (cfg.root / "llm" / "evil.md").symlink_to(outside)
        with pytest.raises(PathSecurityError):
            notes.notes_read(cfg, "llm/evil.md")

    def test_list_outside_root_rejected(self, cfg: NotesConfig) -> None:
        with pytest.raises(PathSecurityError):
            notes.notes_list(cfg, subdir="../..")

    def test_write_outside_whitelist_rejected(self, cfg: NotesConfig) -> None:
        with pytest.raises(WriteNotAllowedError) as exc:
            notes.notes_write(cfg, "ops/x.md", "no", mode="create")
        assert "llm" in str(exc.value) and "inbox" in str(exc.value)
        assert not (cfg.root / "ops" / "x.md").exists()

        with pytest.raises(WriteNotAllowedError):
            notes.notes_write(cfg, "nuovo-top-level.md", "no", mode="create")

    def test_write_traversal_rejected(self, cfg: NotesConfig) -> None:
        # Path che "parte" dalla whitelist ma esce con ..
        with pytest.raises((PathSecurityError, WriteNotAllowedError)):
            notes.notes_write(cfg, "llm/../../evil.md", "no", mode="create")

    def test_write_inside_llm_ok(
        self, cfg: NotesConfig, vault: tuple[Path, Path]
    ) -> None:
        root, bare = vault
        out = notes.notes_write(cfg, "llm/idea.md", "# Idea\n", mode="create")
        assert (root / "llm" / "idea.md").read_text(encoding="utf-8") == "# Idea\n"
        assert out["path"] == "llm/idea.md"
        assert out["pushed"] is True
        assert _bare_has_file(bare, "llm/idea.md")

    def test_write_inside_inbox_ok(
        self, cfg: NotesConfig, vault: tuple[Path, Path]
    ) -> None:
        root, bare = vault
        notes.notes_write(cfg, "inbox/todo.md", "- [ ] x\n", mode="create")
        assert (root / "inbox" / "todo.md").exists()
        assert _bare_has_file(bare, "inbox/todo.md")

    def test_write_nested_subdir_created(
        self, cfg: NotesConfig, vault: tuple[Path, Path]
    ) -> None:
        root, _ = vault
        notes.notes_write(cfg, "llm/2026/07/log.md", "x\n", mode="create")
        assert (root / "llm" / "2026" / "07" / "log.md").exists()


# --- Semantica write ------------------------------------------------------------


class TestWriteSemantics:
    def test_create_fails_if_exists(self, cfg: NotesConfig) -> None:
        notes.notes_write(cfg, "llm/a.md", "v1\n", mode="create")
        with pytest.raises(NotesFileError):
            notes.notes_write(cfg, "llm/a.md", "v2\n", mode="create")
        assert (cfg.root / "llm" / "a.md").read_text(encoding="utf-8") == "v1\n"

    def test_overwrite_and_append(self, cfg: NotesConfig) -> None:
        notes.notes_write(cfg, "llm/a.md", "v1\n", mode="create")
        notes.notes_write(cfg, "llm/a.md", "v2\n", mode="overwrite")
        assert (cfg.root / "llm" / "a.md").read_text(encoding="utf-8") == "v2\n"
        notes.notes_write(cfg, "llm/a.md", "more\n", mode="append")
        assert (
            cfg.root / "llm" / "a.md"
        ).read_text(encoding="utf-8") == "v2\nmore\n"

    def test_invalid_mode_rejected(self, cfg: NotesConfig) -> None:
        with pytest.raises(ValueError):
            notes.notes_write(cfg, "llm/a.md", "x", mode="delete")

    def test_write_non_md_rejected(self, cfg: NotesConfig) -> None:
        with pytest.raises(NotesFileError):
            notes.notes_write(cfg, "inbox/script.sh", "#!/bin/sh\n", mode="create")
        assert not (cfg.root / "inbox" / "script.sh").exists()

    def test_commit_message_format(
        self, cfg: NotesConfig, vault: tuple[Path, Path]
    ) -> None:
        root, _ = vault
        notes.notes_write(cfg, "llm/b.md", "x\n", mode="create")
        assert _last_commit_subject(root) == "notes(mcp): create llm/b.md"
        notes.notes_write(cfg, "llm/b.md", "y\n", mode="overwrite")
        assert _last_commit_subject(root) == "notes(mcp): overwrite llm/b.md"

    def test_one_commit_per_write(
        self, cfg: NotesConfig, vault: tuple[Path, Path]
    ) -> None:
        root, _ = vault
        before = _commit_count(root)
        notes.notes_write(cfg, "llm/c1.md", "x\n", mode="create")
        notes.notes_write(cfg, "llm/c2.md", "y\n", mode="create")
        assert _commit_count(root) == before + 2

    def test_no_force_in_git_invocations(
        self, cfg: NotesConfig, git_recorder: list[list[str]]
    ) -> None:
        notes.notes_write(cfg, "llm/f.md", "x\n", mode="create")
        notes.notes_sync_pull(cfg)
        notes.notes_sync_status(cfg)
        git_cmds = [c for c in git_recorder if "git" in Path(c[0]).name]
        assert git_cmds, "nessun comando git registrato"
        for c in git_cmds:
            assert "--force" not in c, f"--force in {c}"
            assert "--force-with-lease" not in c, f"--force-with-lease in {c}"
            assert "-f" not in c, f"-f in {c}"


# --- Sync -----------------------------------------------------------------------


class TestSync:
    def test_pull_before_write_called(
        self, cfg: NotesConfig, git_recorder: list[list[str]]
    ) -> None:
        notes.notes_write(cfg, "llm/p.md", "x\n", mode="create")
        subcommands = [
            next((a for a in c[1:] if not a.startswith("-")), "")
            for c in git_recorder
            if "git" in Path(c[0]).name
        ]
        assert "pull" in subcommands, f"nessun pull in {subcommands}"
        assert "commit" in subcommands
        assert subcommands.index("pull") < subcommands.index("commit")

    def test_pull_merges_remote_changes(
        self, cfg: NotesConfig, second_clone: Path
    ) -> None:
        (second_clone / "work" / "dal-pc.md").write_text("pc\n", encoding="utf-8")
        _run(second_clone, "git", "add", "work/dal-pc.md")
        _run(second_clone, "git", "commit", "-m", "nota dal pc")
        _run(second_clone, "git", "push")

        out = notes.notes_sync_pull(cfg)
        assert out["updated"] is True
        assert (cfg.root / "work" / "dal-pc.md").exists()

    def test_write_rejected_on_conflicted_tree(
        self, cfg: NotesConfig, vault: tuple[Path, Path], second_clone: Path
    ) -> None:
        root, _ = vault
        # Divergenza in conflitto sulla stessa riga dello stesso file
        (second_clone / "work" / "note1.md").write_text("PC WINS\n", encoding="utf-8")
        _run(second_clone, "git", "add", "work/note1.md")
        _run(second_clone, "git", "commit", "-m", "edit pc")
        _run(second_clone, "git", "push")

        (root / "work" / "note1.md").write_text("DEVBOX WINS\n", encoding="utf-8")
        _run(root, "git", "add", "work/note1.md")
        _run(root, "git", "commit", "-m", "edit devbox")

        with pytest.raises(NotesSyncError):
            notes.notes_write(cfg, "llm/nuova.md", "x\n", mode="create")

        # Il file NON è stato scritto e il tree è tornato pulito (rebase abortito)
        assert not (root / "llm" / "nuova.md").exists()
        status = _run(root, "git", "status", "--porcelain")
        assert "UU" not in status
        assert not (root / ".git" / "rebase-merge").exists()
        assert not (root / ".git" / "rebase-apply").exists()

    def test_sync_status_reports_ahead_behind(
        self, cfg: NotesConfig, vault: tuple[Path, Path], second_clone: Path
    ) -> None:
        root, _ = vault
        st = notes.notes_sync_status(cfg)
        assert st["ahead"] == 0
        assert st["behind"] == 0
        assert st["clean"] is True

        # ahead: commit locale non pushato
        (root / "llm" / "local.md").write_text("x\n", encoding="utf-8")
        _run(root, "git", "add", "llm/local.md")
        _run(root, "git", "commit", "-m", "local only")
        # behind: commit remoto non ancora pullato
        (second_clone / "work" / "remote.md").write_text("y\n", encoding="utf-8")
        _run(second_clone, "git", "add", "work/remote.md")
        _run(second_clone, "git", "commit", "-m", "remote only")
        _run(second_clone, "git", "push")

        st = notes.notes_sync_status(cfg)
        assert st["ahead"] == 1
        assert st["behind"] == 1

    def test_sync_status_reports_dirty_tree(self, cfg: NotesConfig) -> None:
        (cfg.root / "inbox" / "sporco.md").write_text("x\n", encoding="utf-8")
        st = notes.notes_sync_status(cfg)
        assert st["clean"] is False
        assert "inbox/sporco.md" in st["untracked"]


# --- Read / list / search --------------------------------------------------------


class TestReadListSearch:
    def test_list_default_md_only(self, cfg: NotesConfig) -> None:
        (cfg.root / "work" / "raw.txt").write_text("no\n", encoding="utf-8")
        out = notes.notes_list(cfg)
        assert "work/note1.md" in out["files"]
        assert "INDEX.md" in out["files"]
        assert "work/raw.txt" not in out["files"]
        assert out["files"] == sorted(out["files"])
        # .git mai listato
        assert not any(f.startswith(".git") for f in out["files"])

    def test_list_respects_subdir_and_glob(self, cfg: NotesConfig) -> None:
        out = notes.notes_list(cfg, subdir="work", glob="note*.md")
        assert out["files"] == ["work/note1.md"]

    def test_list_respects_limit(
        self, cfg: NotesConfig, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(notes, "MAX_LIST_ENTRIES", 2)
        out = notes.notes_list(cfg)
        assert len(out["files"]) == 2
        assert out["truncated"] is True

    def test_read_ok(self, cfg: NotesConfig) -> None:
        out = notes.notes_read(cfg, "work/note1.md")
        assert "Hello WORLD" in out["content"]
        assert out["path"] == "work/note1.md"

    def test_read_non_md_rejected(self, cfg: NotesConfig) -> None:
        (cfg.root / "work" / "raw.txt").write_text("no\n", encoding="utf-8")
        with pytest.raises(NotesFileError):
            notes.notes_read(cfg, "work/raw.txt")

    def test_read_missing_file(self, cfg: NotesConfig) -> None:
        with pytest.raises(NotesFileError):
            notes.notes_read(cfg, "work/manca.md")

    def test_read_size_limit(self, vault: tuple[Path, Path]) -> None:
        root, _ = vault
        cfg_small = NotesConfig(root=root, max_read_bytes=1024)
        (root / "work" / "big.md").write_text("A" * 2048, encoding="utf-8")
        with pytest.raises(FileTooLargeError):
            notes.notes_read(cfg_small, "work/big.md")

    def test_search_case_insensitive_and_line_numbers(self, cfg: NotesConfig) -> None:
        out = notes.notes_search(cfg, "hello world")
        assert any(
            m.startswith("work/note1.md:3:") for m in out["matches"]
        ), out["matches"]

    def test_search_respects_subdir_and_limit(
        self, cfg: NotesConfig, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        out = notes.notes_search(cfg, "hello", subdir="llm")
        assert out["matches"] == []

        monkeypatch.setattr(notes, "MAX_SEARCH_LINES", 1)
        (cfg.root / "work" / "multi.md").write_text(
            "match uno\nmatch due\n", encoding="utf-8"
        )
        out = notes.notes_search(cfg, "match")
        assert len(out["matches"]) == 1
        assert out["truncated"] is True

    def test_search_empty_query_rejected(self, cfg: NotesConfig) -> None:
        with pytest.raises(ValueError):
            notes.notes_search(cfg, "")


# --- Registrazione server --------------------------------------------------------


class TestServerRegistration:
    async def test_notes_tools_registered(
        self, cfg: NotesConfig, config_ro, tmp_path: Path
    ) -> None:
        from devbox_bridge.server import create_mcp

        mcp = create_mcp(config_ro, notes_config=cfg)
        names = {tool.name for tool in await mcp.list_tools()}
        expected = {
            "notes_list",
            "notes_read",
            "notes_search",
            "notes_write",
            "notes_sync_pull",
            "notes_sync_status",
        }
        assert expected <= names, f"mancano: {expected - names}"
