"""Fixture pytest condivise.

Le fixture qui sono pensate per essere riusate dai test di tools/filesystem,
tools/git e (in futuro) tools/execution. Il pattern: si crea un AppConfig
in-memory che punta a directory temporanee, così i test non toccano
i progetti reali della devbox.
"""

from __future__ import annotations

import hashlib
import os
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
    ) -> AppConfig:
        return _make_config(
            tmp_path,
            tmp_token_file,
            project_name=project_name,
            project_path=project_path,
            write_enabled=write_enabled,
            allow_push=allow_push,
            max_read_bytes=max_read_bytes,
        )

    return _factory


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
