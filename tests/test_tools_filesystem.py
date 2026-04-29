"""Test per tools/filesystem.py.

Categorie:
  - read_file (7)
  - write_file (5)
  - apply_patch (6)
  - list_directory (5)
  - search_files (6)
  - list_projects (2)
"""

from __future__ import annotations

import hashlib
import os
import shutil
from pathlib import Path

import pytest

from devbox_bridge.config import AppConfig
from devbox_bridge.security.paths import PathSecurityError
from devbox_bridge.tools.filesystem import (
    BinaryFileError,
    FileTooLargeError,
    GlobSecurityError,
    RipgrepNotFoundError,
    WriteNotAllowedError,
    apply_patch,
    list_directory,
    list_projects,
    read_file,
    search_files,
    write_file,
)


# --- read_file --------------------------------------------------------------


def test_read_file_success(config_ro: AppConfig) -> None:
    out = read_file(config_ro, "myproj", "README.md")
    assert out["path"] == "README.md"
    assert out["encoding"] == "utf-8"
    assert "Hello world" in out["content"]
    assert out["bytes"] == len(out["content"].encode("utf-8"))
    expected_sha = hashlib.sha256(out["content"].encode("utf-8")).hexdigest()[:8]
    assert out["content_sha8"] == expected_sha


def test_read_file_missing_raises(config_ro: AppConfig) -> None:
    with pytest.raises(FileNotFoundError):
        read_file(config_ro, "myproj", "does/not/exist.md")


def test_read_file_path_traversal_blocked(config_ro: AppConfig) -> None:
    with pytest.raises(PathSecurityError):
        read_file(config_ro, "myproj", "../../etc/passwd")


def test_read_file_above_max_read_bytes_refused(
    config_factory, tmp_project_root: Path
) -> None:
    big = tmp_project_root / "big.txt"
    big.write_text("x" * 5000, encoding="utf-8")
    cfg = config_factory(tmp_project_root, max_read_bytes=2048)
    with pytest.raises(FileTooLargeError):
        read_file(cfg, "myproj", "big.txt")


def test_read_file_binary_refused(config_ro: AppConfig, tmp_project_root: Path) -> None:
    (tmp_project_root / "bin.dat").write_bytes(b"abc\x00def")
    with pytest.raises(BinaryFileError):
        read_file(config_ro, "myproj", "bin.dat")


def test_read_file_invalid_utf8_refused(
    config_ro: AppConfig, tmp_project_root: Path
) -> None:
    # bytes 0xFF 0xFE 0xFD = sequenza non valida UTF-8, ma niente \x00
    (tmp_project_root / "bad.txt").write_bytes(b"hello\xff\xfe\xfd")
    with pytest.raises(UnicodeDecodeError):
        read_file(config_ro, "myproj", "bad.txt")


def test_read_file_content_sha8_deterministic(
    config_ro: AppConfig, tmp_project_root: Path
) -> None:
    (tmp_project_root / "fixed.txt").write_text("identical content\n", encoding="utf-8")
    a = read_file(config_ro, "myproj", "fixed.txt")
    b = read_file(config_ro, "myproj", "fixed.txt")
    assert a["content_sha8"] == b["content_sha8"]
    assert len(a["content_sha8"]) == 8


# --- write_file -------------------------------------------------------------


def test_write_file_create_new(config_rw: AppConfig, tmp_project_root: Path) -> None:
    out = write_file(
        config_rw, "myproj", "src/new.py", "x = 1\n", create=True
    )
    assert out["created"] is True
    assert (tmp_project_root / "src" / "new.py").read_text() == "x = 1\n"


def test_write_file_overwrite_existing(
    config_rw: AppConfig, tmp_project_root: Path
) -> None:
    out = write_file(config_rw, "myproj", "README.md", "# Replaced\n")
    assert out["created"] is False
    assert (tmp_project_root / "README.md").read_text() == "# Replaced\n"


def test_write_file_denied_when_write_disabled(config_ro: AppConfig) -> None:
    with pytest.raises(WriteNotAllowedError):
        write_file(config_ro, "myproj", "README.md", "nope")


def test_write_file_path_traversal_blocked(config_rw: AppConfig) -> None:
    with pytest.raises(PathSecurityError):
        write_file(config_rw, "myproj", "../escape.txt", "nope", create=True)


def test_write_file_create_false_on_missing_raises(config_rw: AppConfig) -> None:
    with pytest.raises(FileNotFoundError):
        write_file(config_rw, "myproj", "src/brand_new.py", "x", create=False)


# --- apply_patch ------------------------------------------------------------


def test_apply_patch_success(
    config_rw: AppConfig, tmp_project_root: Path
) -> None:
    before = (tmp_project_root / "src" / "main.py").read_bytes()
    out = apply_patch(
        config_rw, "myproj", "src/main.py",
        old="hello from main", new="ciao dal main",
    )
    assert out["occurrences_replaced"] == 1
    assert out["content_sha8_before"] == hashlib.sha256(before).hexdigest()[:8]
    after = (tmp_project_root / "src" / "main.py").read_bytes()
    assert out["content_sha8_after"] == hashlib.sha256(after).hexdigest()[:8]
    assert out["content_sha8_before"] != out["content_sha8_after"]
    assert b"ciao dal main" in after


def test_apply_patch_old_not_found(config_rw: AppConfig) -> None:
    with pytest.raises(ValueError, match="non trovato"):
        apply_patch(
            config_rw, "myproj", "src/main.py",
            old="nonexistent_string_xyz", new="anything",
        )


def test_apply_patch_multiple_occurrences_replaced(
    config_rw: AppConfig, tmp_project_root: Path
) -> None:
    (tmp_project_root / "multi.txt").write_text("foo bar foo baz foo\n", encoding="utf-8")
    out = apply_patch(
        config_rw, "myproj", "multi.txt", old="foo", new="FOO",
    )
    assert out["occurrences_replaced"] == 3
    assert (tmp_project_root / "multi.txt").read_text() == "FOO bar FOO baz FOO\n"


def test_apply_patch_old_equals_new_refused(config_rw: AppConfig) -> None:
    with pytest.raises(ValueError, match="identici"):
        apply_patch(
            config_rw, "myproj", "src/main.py", old="hello", new="hello",
        )


def test_apply_patch_binary_refused(
    config_rw: AppConfig, tmp_project_root: Path
) -> None:
    (tmp_project_root / "bin.dat").write_bytes(b"abc\x00def")
    with pytest.raises(BinaryFileError):
        apply_patch(
            config_rw, "myproj", "bin.dat", old="abc", new="xyz",
        )


def test_apply_patch_denied_when_write_disabled(config_ro: AppConfig) -> None:
    with pytest.raises(WriteNotAllowedError):
        apply_patch(
            config_ro, "myproj", "src/main.py", old="main", new="MAIN",
        )


# --- list_directory ---------------------------------------------------------


def test_list_directory_root_lists_top_level(config_ro: AppConfig) -> None:
    out = list_directory(config_ro, "myproj", ".")
    names = {e["name"] for e in out["entries"]}
    assert {"README.md", "src", "tests", "node_modules", ".git", "build"}.issubset(names)


def test_list_directory_marks_skipped_dirs(config_ro: AppConfig) -> None:
    out = list_directory(config_ro, "myproj", ".")
    by_name = {e["name"]: e for e in out["entries"]}
    assert by_name["node_modules"]["type"] == "dir"
    assert by_name["node_modules"]["skipped"] is True
    assert by_name[".git"]["skipped"] is True
    assert by_name["build"]["skipped"] is True
    assert by_name["src"]["skipped"] is False


def test_list_directory_file_has_size(config_ro: AppConfig, tmp_project_root: Path) -> None:
    out = list_directory(config_ro, "myproj", ".")
    readme = next(e for e in out["entries"] if e["name"] == "README.md")
    assert readme["type"] == "file"
    assert readme["size"] == (tmp_project_root / "README.md").stat().st_size


def test_list_directory_internal_symlink(
    config_ro: AppConfig, tmp_project_root: Path
) -> None:
    (tmp_project_root / "link_to_readme").symlink_to(tmp_project_root / "README.md")
    out = list_directory(config_ro, "myproj", ".")
    link = next(e for e in out["entries"] if e["name"] == "link_to_readme")
    assert link["type"] == "symlink"
    assert link["target"] == "README.md"


def test_list_directory_external_symlink_marked(
    config_ro: AppConfig, tmp_project_root: Path, tmp_path: Path
) -> None:
    outside = tmp_path / "outside_target"
    outside.write_text("outside\n")
    (tmp_project_root / "link_external").symlink_to(outside)
    out = list_directory(config_ro, "myproj", ".")
    link = next(e for e in out["entries"] if e["name"] == "link_external")
    assert link["type"] == "symlink"
    assert link["target"] == "<external>"


# --- search_files -----------------------------------------------------------


@pytest.fixture
def _require_rg() -> None:
    if shutil.which("rg") is None:
        pytest.skip("ripgrep not installed; required by search_files tests")


def test_search_files_finds_match(
    _require_rg: None, config_ro: AppConfig
) -> None:
    out = search_files(config_ro, "myproj", "hello from main")
    assert out["match_count"] >= 1
    paths = {m["path"] for m in out["matches"]}
    assert any("main.py" in p for p in paths)


def test_search_files_skips_excluded_dirs(
    _require_rg: None, config_ro: AppConfig, tmp_project_root: Path
) -> None:
    # Inseriamo lo stesso pattern in src/ (visibile) e in node_modules (skipped)
    (tmp_project_root / "src" / "marker.py").write_text(
        "UNIQUEMARKER_XYZ\n", encoding="utf-8"
    )
    (tmp_project_root / "node_modules" / "foo" / "tainted.js").write_text(
        "UNIQUEMARKER_XYZ\n", encoding="utf-8"
    )
    out = search_files(config_ro, "myproj", "UNIQUEMARKER_XYZ")
    assert out["match_count"] == 1
    assert "src/marker.py" in out["matches"][0]["path"]


def test_search_files_glob_traversal_refused(
    _require_rg: None, config_ro: AppConfig
) -> None:
    with pytest.raises((GlobSecurityError, PathSecurityError)):
        search_files(config_ro, "myproj", "anything", glob="../../../etc/*")


def test_search_files_glob_absolute_refused(
    _require_rg: None, config_ro: AppConfig
) -> None:
    with pytest.raises((GlobSecurityError, PathSecurityError)):
        search_files(config_ro, "myproj", "anything", glob="/etc/*")


def test_search_files_max_matches_truncates(
    _require_rg: None, config_ro: AppConfig, tmp_project_root: Path
) -> None:
    big = tmp_project_root / "many.txt"
    big.write_text("\n".join(["needle"] * 50) + "\n", encoding="utf-8")
    out = search_files(config_ro, "myproj", "needle", max_matches=10)
    assert out["match_count"] == 10
    assert out["truncated"] is True


def test_search_files_ripgrep_missing_raises(
    config_ro: AppConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Forza un PATH dove rg non c'è
    monkeypatch.setenv("PATH", "/nonexistent-path-xyz")
    with pytest.raises(RipgrepNotFoundError):
        search_files(config_ro, "myproj", "anything")


# --- list_projects ----------------------------------------------------------


def test_list_projects_returns_minimal_shape(config_rw: AppConfig) -> None:
    out = list_projects(config_rw)
    assert len(out) == 1
    p = out[0]
    assert set(p.keys()) == {
        "name",
        "path",
        "write_enabled",
        "allow_push",
        "has_test_command",
        "has_lint_command",
        "has_build_command",
    }
    assert p["name"] == "myproj"
    assert p["write_enabled"] is True
    assert p["has_test_command"] is False


def test_list_projects_does_not_leak_internal_fields(
    config_rw: AppConfig,
) -> None:
    out = list_projects(config_rw)
    forbidden = {"command_whitelist", "env_passthrough", "max_read_bytes"}
    assert not any(k in out[0] for k in forbidden)


# --- edge: directory passata a tool che vuole un file ----------------------


def test_read_file_on_directory_raises(config_ro: AppConfig) -> None:
    with pytest.raises(IsADirectoryError):
        read_file(config_ro, "myproj", "src")


def test_write_file_target_is_directory_raises(config_rw: AppConfig) -> None:
    with pytest.raises(IsADirectoryError):
        write_file(config_rw, "myproj", "src", "content")


def test_apply_patch_on_missing_file_raises(config_rw: AppConfig) -> None:
    with pytest.raises(FileNotFoundError):
        apply_patch(
            config_rw, "myproj", "does/not/exist.txt", old="x", new="y"
        )


def test_apply_patch_on_directory_raises(config_rw: AppConfig) -> None:
    with pytest.raises(IsADirectoryError):
        apply_patch(config_rw, "myproj", "src", old="x", new="y")


# --- glob input edge -------------------------------------------------------


def test_search_files_glob_empty_refused(
    _require_rg: None, config_ro: AppConfig
) -> None:
    with pytest.raises(GlobSecurityError):
        search_files(config_ro, "myproj", "anything", glob="")


def test_search_files_glob_home_relative_refused(
    _require_rg: None, config_ro: AppConfig
) -> None:
    with pytest.raises(GlobSecurityError):
        search_files(config_ro, "myproj", "anything", glob="~/foo")


def test_search_files_max_matches_zero_refused(
    _require_rg: None, config_ro: AppConfig
) -> None:
    with pytest.raises(ValueError):
        search_files(config_ro, "myproj", "anything", max_matches=0)
