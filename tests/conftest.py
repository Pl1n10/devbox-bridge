"""Fixture pytest condivise.

Le fixture qui sono pensate per essere riusate dai test di tools/filesystem,
tools/git e (in futuro) tools/execution. Il pattern: si crea un AppConfig
in-memory che punta a directory temporanee, così i test non toccano
i progetti reali della devbox.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import textwrap
from pathlib import Path
from typing import Any

import pytest

from devbox_bridge.config import (
    AppConfig,
    AuditConfig,
    AuthConfig,
    ProjectConfig,
    ServerConfig,
)


@pytest.fixture
def tmp_token_file(tmp_path: Path) -> Path:
    """File contenente lo SHA-256 di un token noto ('test-token-123')."""
    token = "test-token-123"
    h = hashlib.sha256(token.encode("utf-8")).hexdigest()
    p = tmp_path / "token.sha256"
    p.write_text(h + "\n", encoding="utf-8")
    return p


@pytest.fixture
def tmp_project_root(tmp_path: Path) -> Path:
    """Project root con un layout minimale ma rappresentativo:
      ./README.md
      ./src/main.py
      ./src/util.py
      ./tests/test_main.py
      ./node_modules/foo/package.json   (skip dir)
      ./.git/HEAD                       (skip dir)
      ./build/artifact.bin              (skip dir)
    """
    root = tmp_path / "myproj"
    (root / "src").mkdir(parents=True)
    (root / "tests").mkdir()
    (root / "node_modules" / "foo").mkdir(parents=True)
    (root / ".git").mkdir()
    (root / "build").mkdir()

    (root / "README.md").write_text("# myproj\n\nHello world.\n", encoding="utf-8")
    (root / "src" / "main.py").write_text(
        textwrap.dedent(
            """\
            def main() -> None:
                print("hello from main")


            if __name__ == "__main__":
                main()
            """
        ),
        encoding="utf-8",
    )
    (root / "src" / "util.py").write_text(
        "def add(a: int, b: int) -> int:\n    return a + b\n",
        encoding="utf-8",
    )
    (root / "tests" / "test_main.py").write_text(
        "def test_smoke() -> None:\n    assert True\n",
        encoding="utf-8",
    )
    (root / "node_modules" / "foo" / "package.json").write_text(
        '{"name": "foo"}\n', encoding="utf-8"
    )
    (root / ".git" / "HEAD").write_text(
        "ref: refs/heads/main\n", encoding="utf-8"
    )
    (root / "build" / "artifact.bin").write_bytes(b"\x00\x01\x02binary\x00")
    return root


@pytest.fixture
def tmp_project_root_ro(tmp_project_root: Path) -> Path:
    """Alias semantico per progetti read-only nei test."""
    return tmp_project_root


def _make_config(
    tmp_path: Path,
    tmp_token_file: Path,
    *,
    project_name: str,
    project_path: Path,
    write_enabled: bool,
    allow_push: bool = False,
    max_read_bytes: int | None = None,
    test_command: str | None = None,
    lint_command: str | None = None,
    build_command: str | None = None,
    command_whitelist: list[str] | None = None,
    env_passthrough: list[str] | None = None,
) -> AppConfig:
    return AppConfig(
        server=ServerConfig(
            bind="127.0.0.1:8765",
            log_level="INFO",
            log_dir=tmp_path / "logs",
        ),
        auth=AuthConfig(token_hash_file=tmp_token_file),
        audit=AuditConfig(
            log_dir=tmp_path / "logs" / "audit",
            audit_reads=False,
        ),
        projects={
            project_name: ProjectConfig(
                path=project_path,
                write_enabled=write_enabled,
                allow_push=allow_push,
                max_read_bytes=max_read_bytes,
                test_command=test_command,
                lint_command=lint_command,
                build_command=build_command,
                command_whitelist=command_whitelist or [],
                env_passthrough=env_passthrough or [],
            )
        },
    )


@pytest.fixture
def config_ro(
    tmp_path: Path, tmp_token_file: Path, tmp_project_root: Path
) -> AppConfig:
    """AppConfig con un progetto write_enabled=False."""
    return _make_config(
        tmp_path,
        tmp_token_file,
        project_name="myproj",
        project_path=tmp_project_root,
        write_enabled=False,
    )


@pytest.fixture
def config_rw(
    tmp_path: Path, tmp_token_file: Path, tmp_project_root: Path
) -> AppConfig:
    """AppConfig con un progetto write_enabled=True."""
    return _make_config(
        tmp_path,
        tmp_token_file,
        project_name="myproj",
        project_path=tmp_project_root,
        write_enabled=True,
    )


@pytest.fixture
def config_factory(
    tmp_path: Path, tmp_token_file: Path
) -> Any:
    """Factory parametrica per i test che vogliono override (max_read_bytes, ecc.)."""

    def _factory(
        project_path: Path,
        *,
        project_name: str = "myproj",
        write_enabled: bool = False,
        allow_push: bool = False,
        max_read_bytes: int | None = None,
        test_command: str | None = None,
        lint_command: str | None = None,
        build_command: str | None = None,
        command_whitelist: list[str] | None = None,
        env_passthrough: list[str] | None = None,
    ) -> AppConfig:
        return _make_config(
            tmp_path,
            tmp_token_file,
            project_name=project_name,
            project_path=project_path,
            write_enabled=write_enabled,
            allow_push=allow_push,
            max_read_bytes=max_read_bytes,
            test_command=test_command,
            lint_command=lint_command,
            build_command=build_command,
            command_whitelist=command_whitelist,
            env_passthrough=env_passthrough,
        )

    return _factory


@pytest.fixture
def tmp_git_repo(tmp_path: Path) -> Path:
    """Project root con repo git inizializzato e 2 commit minimi.

    Layout:
      ./README.md     (committed)
      ./src/main.py   (committed)
    Branch iniziale: `main` (forzato a `git init -b main` per determinismo).
    Identità locale: `Test <test@example.com>`, `commit.gpgsign=false`.
    """
    if shutil.which("git") is None:
        pytest.skip("git non disponibile")

    root = tmp_path / "gitproj"
    root.mkdir()
    (root / "src").mkdir()
    (root / "README.md").write_text("# gitproj\n", encoding="utf-8")
    (root / "src" / "main.py").write_text(
        "def main() -> None:\n    print('hi')\n", encoding="utf-8"
    )

    def run(*cmd: str) -> None:
        subprocess.run(
            list(cmd),
            cwd=root,
            check=True,
            capture_output=True,
            text=True,
        )

    run("git", "init", "-b", "main")
    run("git", "config", "user.email", "test@example.com")
    run("git", "config", "user.name", "Test")
    run("git", "config", "commit.gpgsign", "false")
    run("git", "add", "README.md")
    run("git", "commit", "-m", "initial commit")
    run("git", "add", "src/main.py")
    run("git", "commit", "-m", "add main")

    return root


@pytest.fixture
def tmp_git_repo_with_origin(tmp_git_repo: Path, tmp_path: Path) -> tuple[Path, Path]:
    """tmp_git_repo + un bare repo locale come `origin`.

    Il bare repo è in `<tmp_path>/origin.git`. Permette di testare git_push
    senza rete ed evitando dipendenze esterne.
    """
    bare = tmp_path / "origin.git"
    subprocess.run(
        ["git", "init", "--bare", "-b", "main", str(bare)],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "remote", "add", "origin", str(bare)],
        cwd=tmp_git_repo,
        check=True,
        capture_output=True,
    )
    return tmp_git_repo, bare


@pytest.fixture
def config_git_ro(
    tmp_path: Path, tmp_token_file: Path, tmp_git_repo: Path
) -> AppConfig:
    """AppConfig su repo git, write_enabled=False."""
    return _make_config(
        tmp_path,
        tmp_token_file,
        project_name="gitproj",
        project_path=tmp_git_repo,
        write_enabled=False,
    )


@pytest.fixture
def config_git_rw(
    tmp_path: Path, tmp_token_file: Path, tmp_git_repo: Path
) -> AppConfig:
    """AppConfig su repo git, write_enabled=True, allow_push=False."""
    return _make_config(
        tmp_path,
        tmp_token_file,
        project_name="gitproj",
        project_path=tmp_git_repo,
        write_enabled=True,
    )


@pytest.fixture
def config_git_push(
    tmp_path: Path,
    tmp_token_file: Path,
    tmp_git_repo_with_origin: tuple[Path, Path],
) -> AppConfig:
    """AppConfig su repo git con remote bare locale, allow_push=True."""
    repo, _bare = tmp_git_repo_with_origin
    return _make_config(
        tmp_path,
        tmp_token_file,
        project_name="gitproj",
        project_path=repo,
        write_enabled=True,
        allow_push=True,
    )


@pytest.fixture(autouse=True)
def _no_proxy_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pulisce variabili che potrebbero alterare subprocess di rg/git."""
    for var in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"):
        monkeypatch.delenv(var, raising=False)
    # Forza locale C per output deterministico
    monkeypatch.setenv("LC_ALL", "C")
    monkeypatch.setenv("LANG", "C")
    # Path minimale ma con /usr/bin per rg/git
    if "PATH" not in os.environ:
        monkeypatch.setenv("PATH", "/usr/bin:/bin")
