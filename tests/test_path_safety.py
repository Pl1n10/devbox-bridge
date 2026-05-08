"""Test path traversal — security/paths.py."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from devbox_bridge.config import ConfigError, load_config
from devbox_bridge.security.paths import (
    PathSecurityError,
    resolve_project_path,
    resolve_within,
    resolve_within_any,
)


@pytest.fixture
def project_root(tmp_path: Path) -> Path:
    root = tmp_path / "myproject"
    root.mkdir()
    (root / "src").mkdir()
    (root / "src" / "app.py").write_text("# code", encoding="utf-8")
    (root / "README.md").write_text("# proj", encoding="utf-8")
    return root


# --- positive ---


def test_resolve_relative_path_inside(project_root: Path) -> None:
    p = resolve_within(project_root, "src/app.py")
    assert p == (project_root / "src" / "app.py").resolve()


def test_resolve_root_itself(project_root: Path) -> None:
    p = resolve_within(project_root, ".")
    assert p == project_root.resolve()


def test_resolve_absolute_path_inside(project_root: Path) -> None:
    abs_path = project_root / "README.md"
    p = resolve_within(project_root, abs_path)
    assert p == abs_path.resolve()


def test_resolve_nonexistent_file_inside_ok(project_root: Path) -> None:
    """write_file su file nuovo non deve fallire al check."""
    p = resolve_within(project_root, "src/new_file.py")
    assert p == (project_root / "src" / "new_file.py").resolve()


def test_empty_path_resolves_to_root(project_root: Path) -> None:
    """Path vuoto → trattato come '.' → ritorna la root."""
    p = resolve_within(project_root, "")
    assert p == project_root.resolve()


# --- negative: traversal ---


def test_dotdot_traversal_rejected(project_root: Path) -> None:
    with pytest.raises(PathSecurityError, match="esce"):
        resolve_within(project_root, "../outside.txt")


def test_nested_dotdot_rejected(project_root: Path) -> None:
    with pytest.raises(PathSecurityError, match="esce"):
        resolve_within(project_root, "src/../../../../etc/passwd")


def test_absolute_outside_rejected(project_root: Path) -> None:
    with pytest.raises(PathSecurityError, match="esce"):
        resolve_within(project_root, "/etc/passwd")


def test_absolute_to_other_project_rejected(project_root: Path, tmp_path: Path) -> None:
    other = tmp_path / "otherproject"
    other.mkdir()
    (other / "secret.txt").write_text("nope", encoding="utf-8")
    with pytest.raises(PathSecurityError, match="esce"):
        resolve_within(project_root, other / "secret.txt")


def test_null_byte_in_path_rejected(project_root: Path) -> None:
    """Null byte in path → ValueError (Python lo blocca a livello di Path)."""
    with pytest.raises((PathSecurityError, ValueError)):
        resolve_within(project_root, "foo\x00bar")


# --- negative: symlink ---


@pytest.mark.skipif(sys.platform == "win32", reason="symlink semantica diversa su Windows")
def test_symlink_escaping_rejected(project_root: Path, tmp_path: Path) -> None:
    """Symlink dentro al progetto che punta fuori → rejected."""
    target = tmp_path / "escape_target"
    target.mkdir()
    (target / "secret.txt").write_text("nope", encoding="utf-8")
    (project_root / "evil_link").symlink_to(target)
    with pytest.raises(PathSecurityError, match="esce"):
        resolve_within(project_root, "evil_link/secret.txt")


@pytest.mark.skipif(sys.platform == "win32", reason="symlink semantica diversa su Windows")
def test_symlink_inside_ok(project_root: Path) -> None:
    """Symlink dentro al progetto che punta dentro al progetto → ok."""
    (project_root / "src" / "link_to_root").symlink_to(project_root)
    p = resolve_within(project_root, "src/link_to_root/README.md")
    assert p == (project_root / "README.md").resolve()


# --- nonexistent project_root ---


def test_nonexistent_project_root_raises(tmp_path: Path) -> None:
    with pytest.raises(PathSecurityError, match="non esiste"):
        resolve_within(tmp_path / "nope", "x.txt")


# --- resolve_project_path integration ---


def _build_cfg(tmp_path: Path, projects: dict[str, Path]) -> Path:
    lines = [
        "auth:",
        f'  token_hash_file: "{tmp_path / "hash"}"',
        "projects:",
    ]
    if projects:
        for name, root in projects.items():
            lines.extend(
                [
                    f"  {name}:",
                    f'    path: "{root}"',
                ]
            )
    else:
        lines.append("  {}")
    cfg_path = tmp_path / "config.yaml"
    cfg_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return cfg_path


def test_resolve_project_path_via_config(tmp_path: Path) -> None:
    root = tmp_path / "myproj"
    root.mkdir()
    (root / "f.txt").write_text("hi", encoding="utf-8")

    cfg = load_config(_build_cfg(tmp_path, {"myproj": root}))
    p = resolve_project_path(cfg, "myproj", "f.txt")
    assert p == (root / "f.txt").resolve()


def test_resolve_project_path_unknown_project(tmp_path: Path) -> None:
    cfg_yaml = f"""
auth:
  token_hash_file: "{tmp_path / "hash"}"
projects: {{}}
"""
    cfg_path = tmp_path / "config.yaml"
    cfg_path.write_text(cfg_yaml, encoding="utf-8")
    cfg = load_config(cfg_path)

    with pytest.raises(ConfigError, match="non in config"):
        resolve_project_path(cfg, "missing", "x.txt")


def test_resolve_project_path_traversal(tmp_path: Path) -> None:
    root = tmp_path / "p"
    root.mkdir()
    cfg = load_config(_build_cfg(tmp_path, {"p": root}))

    with pytest.raises(PathSecurityError):
        resolve_project_path(cfg, "p", "../../etc/passwd")


# --- resolve_within_any -----------------------------------------------------


def test_resolve_within_any_match_first_root(tmp_path: Path) -> None:
    root = tmp_path / "logs"
    root.mkdir()
    f = root / "a.log"
    f.write_text("hello", encoding="utf-8")
    resolved = resolve_within_any(f, [root])
    assert resolved == f.resolve(strict=True)


def test_resolve_within_any_match_second_root(tmp_path: Path) -> None:
    root1 = tmp_path / "first"
    root2 = tmp_path / "second"
    root1.mkdir()
    root2.mkdir()
    f = root2 / "x.log"
    f.write_text("ok", encoding="utf-8")
    resolved = resolve_within_any(f, [root1, root2])
    assert resolved == f.resolve(strict=True)


def test_resolve_within_any_no_match_raises(tmp_path: Path) -> None:
    root = tmp_path / "logs"
    root.mkdir()
    other = tmp_path / "other"
    other.mkdir()
    f = other / "x.log"
    f.write_text("nope", encoding="utf-8")
    with pytest.raises(PathSecurityError, match="non è dentro"):
        resolve_within_any(f, [root])


def test_resolve_within_any_relative_rejected(tmp_path: Path) -> None:
    root = tmp_path / "logs"
    root.mkdir()
    with pytest.raises(PathSecurityError, match="assoluto"):
        resolve_within_any("relative.log", [root])


def test_resolve_within_any_nonexistent_propagates(tmp_path: Path) -> None:
    root = tmp_path / "logs"
    root.mkdir()
    nope = root / "missing.log"
    with pytest.raises(FileNotFoundError):
        resolve_within_any(nope, [root])


def test_resolve_within_any_symlink_escaping_whitelist_rejected(
    tmp_path: Path,
) -> None:
    """Symlink dentro la whitelist che punta FUORI deve essere rifiutato.
    È il classico bypass: /var/log/devbox-bridge/x → /etc/passwd."""
    root = tmp_path / "whitelisted"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    target = outside / "secret.txt"
    target.write_text("secret", encoding="utf-8")
    link = root / "innocent.log"
    link.symlink_to(target)

    with pytest.raises(PathSecurityError, match="non è dentro"):
        resolve_within_any(link, [root])


def test_resolve_within_any_outside_whitelist_nonexistent_path_rejected(
    tmp_path: Path,
) -> None:
    """Un path fuori whitelist che NON esiste deve sollevare PathSecurityError,
    non FileNotFoundError. Razionale: se sollevasse FileNotFoundError, il
    chiamante distinguerebbe "fuori whitelist" da "non esiste" → un attaccante
    potrebbe enumerare quali path esistono nel filesystem fuori dalla whitelist
    osservando il tipo di errore (info-leak debole). Mettendo il check
    whitelist PRIMA dell'esistenza, chiunque chiami con un path fuori
    whitelist riceve sempre lo stesso errore, indipendentemente dal fatto
    che il file esista o meno."""
    root = tmp_path / "whitelist"
    root.mkdir()
    outside_nonexistent = tmp_path / "outside" / "nope.log"
    # NB: outside_nonexistent.parent NON esiste neppure
    with pytest.raises(PathSecurityError, match="non è dentro"):
        resolve_within_any(outside_nonexistent, [root])


def test_resolve_within_any_inside_whitelist_nonexistent_propagates(
    tmp_path: Path,
) -> None:
    """Specularmente: path dentro whitelist ma inesistente → FileNotFoundError.
    Il chiamante (es. tail_log) lo mappa su LogPathNotFoundError, distinto
    da LogPathNotAllowedError. Questo test fissa il contratto rispetto
    al precedente: la whitelist viene controllata, il file non esiste,
    è un caso legittimo da segnalare al chiamante."""
    root = tmp_path / "logs"
    root.mkdir()
    inside_nonexistent = root / "today.log"
    with pytest.raises(FileNotFoundError):
        resolve_within_any(inside_nonexistent, [root])


def test_resolve_within_any_skips_nonexistent_root(tmp_path: Path) -> None:
    """Root inesistente NON solleva: viene saltato silenziosamente
    (mountpoint smontato non rompe il sistema)."""
    real = tmp_path / "real"
    real.mkdir()
    f = real / "a.log"
    f.write_text("ok", encoding="utf-8")
    nonexistent = tmp_path / "missing-mountpoint"
    resolved = resolve_within_any(f, [nonexistent, real])
    assert resolved == f.resolve(strict=True)
