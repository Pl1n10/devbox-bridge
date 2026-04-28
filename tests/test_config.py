"""Test config.py — caricamento, validazione, errori leggibili."""

from __future__ import annotations

from pathlib import Path

import pytest

from devbox_bridge.config import (
    AppConfig,
    ConfigError,
    ProjectConfig,
    load_config,
)

VALID_YAML = """
server:
  bind: "127.0.0.1:8765"
  log_level: "INFO"
  log_dir: "/var/log/devbox-bridge"
auth:
  token_hash_file: "/etc/devbox-bridge/token.sha256"
projects:
  example:
    path: "/home/hypn0/projects/example"
    write_enabled: false
    allow_push: false
    test_command: "pytest -x"
    command_whitelist:
      - "^pytest( .*)?$"
    env_passthrough:
      - "DATABASE_URL_TEST"
"""


def write_yaml(tmp_path: Path, content: str) -> Path:
    p = tmp_path / "config.yaml"
    p.write_text(content, encoding="utf-8")
    return p


def test_load_valid_config(tmp_path: Path) -> None:
    cfg = load_config(write_yaml(tmp_path, VALID_YAML))
    assert isinstance(cfg, AppConfig)
    assert cfg.server.bind == "127.0.0.1:8765"
    assert cfg.server.log_level == "INFO"
    assert cfg.auth.token_hash_file == Path("/etc/devbox-bridge/token.sha256")
    assert "example" in cfg.projects
    assert cfg.projects["example"].test_command == "pytest -x"
    assert cfg.projects["example"].env_passthrough == ["DATABASE_URL_TEST"]


def test_defaults_applied_when_omitted(tmp_path: Path) -> None:
    minimal = """
auth:
  token_hash_file: "/etc/devbox-bridge/token.sha256"
projects: {}
"""
    cfg = load_config(write_yaml(tmp_path, minimal))
    assert cfg.server.bind == "127.0.0.1:8765"
    assert cfg.server.log_level == "INFO"
    assert cfg.projects == {}


def test_missing_file_raises(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="non trovato"):
        load_config(tmp_path / "non-esiste.yaml")


def test_empty_file_raises(tmp_path: Path) -> None:
    p = tmp_path / "empty.yaml"
    p.write_text("", encoding="utf-8")
    with pytest.raises(ConfigError, match="vuoto"):
        load_config(p)


def test_invalid_yaml_raises(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="YAML non valido"):
        load_config(write_yaml(tmp_path, "key: : ::"))


def test_unknown_top_level_field_rejected(tmp_path: Path) -> None:
    bad = VALID_YAML + "\nintruder: oops\n"
    with pytest.raises(ConfigError):
        load_config(write_yaml(tmp_path, bad))


def test_invalid_bind_rejected(tmp_path: Path) -> None:
    bad = VALID_YAML.replace('bind: "127.0.0.1:8765"', 'bind: "127.0.0.1:99999"')
    with pytest.raises(ConfigError, match="bind"):
        load_config(write_yaml(tmp_path, bad))


def test_invalid_log_level_rejected(tmp_path: Path) -> None:
    bad = VALID_YAML.replace('log_level: "INFO"', 'log_level: "BANANA"')
    with pytest.raises(ConfigError, match="log_level"):
        load_config(write_yaml(tmp_path, bad))


def test_relative_log_dir_rejected(tmp_path: Path) -> None:
    bad = VALID_YAML.replace(
        'log_dir: "/var/log/devbox-bridge"',
        'log_dir: "var/log/devbox-bridge"',
    )
    with pytest.raises(ConfigError, match="assoluto"):
        load_config(write_yaml(tmp_path, bad))


def test_relative_project_path_rejected(tmp_path: Path) -> None:
    bad = VALID_YAML.replace(
        'path: "/home/hypn0/projects/example"',
        'path: "relative/path"',
    )
    with pytest.raises(ConfigError, match="assoluto"):
        load_config(write_yaml(tmp_path, bad))


def test_invalid_project_name_rejected(tmp_path: Path) -> None:
    bad = VALID_YAML.replace("example:", "Example_BAD:")
    with pytest.raises(ConfigError):
        load_config(write_yaml(tmp_path, bad))


def test_uncompilable_whitelist_rejected(tmp_path: Path) -> None:
    bad = VALID_YAML.replace('"^pytest( .*)?$"', '"^pytest([invalid"')
    with pytest.raises(ConfigError, match="non compila"):
        load_config(write_yaml(tmp_path, bad))


def test_invalid_env_var_name_rejected(tmp_path: Path) -> None:
    bad = VALID_YAML.replace('"DATABASE_URL_TEST"', '"lowercase_var"')
    with pytest.raises(ConfigError, match="env_passthrough"):
        load_config(write_yaml(tmp_path, bad))


def test_allow_push_without_write_enabled_rejected(tmp_path: Path) -> None:
    bad = VALID_YAML.replace("allow_push: false", "allow_push: true")
    with pytest.raises(ConfigError, match="write_enabled"):
        load_config(write_yaml(tmp_path, bad))


def test_duplicate_project_paths_rejected(tmp_path: Path) -> None:
    duplicate = """
auth:
  token_hash_file: "/etc/devbox-bridge/token.sha256"
projects:
  one:
    path: "/tmp/x"
  two:
    path: "/tmp/x"
"""
    with pytest.raises(ConfigError, match="stesso path"):
        load_config(write_yaml(tmp_path, duplicate))


def test_project_lookup_helper(tmp_path: Path) -> None:
    cfg = load_config(write_yaml(tmp_path, VALID_YAML))
    assert isinstance(cfg.project("example"), ProjectConfig)
    with pytest.raises(ConfigError, match="non in config"):
        cfg.project("missing")


def test_config_yaml_example_is_valid() -> None:
    """Sanity: il file config.yaml.example committato deve sempre essere valido."""
    repo_root = Path(__file__).resolve().parent.parent
    cfg = load_config(repo_root / "config.yaml.example")
    assert "devbox-bridge" in cfg.projects
