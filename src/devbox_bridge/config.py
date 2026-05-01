"""Caricamento e validazione di config.yaml."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Annotated

import yaml
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)


class ConfigError(ValueError):
    """Errore di validazione/caricamento di config.yaml."""


# Nome progetto: solo [a-z0-9-], 1..64 char. Usato come chiave di routing nei tool MCP.
ProjectName = Annotated[
    str,
    StringConstraints(pattern=r"^[a-z0-9][a-z0-9-]{0,63}$"),
]


def _require_absolute(v: Path, field: str) -> Path:
    """Richiede path assoluto; espande ~ ma non risolve symlink (lo fa security/paths.py)."""
    expanded = Path(v).expanduser()
    if not expanded.is_absolute():
        raise ValueError(f"{field} '{v}' deve essere assoluto")
    return expanded


class ServerConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    bind: str = Field(default="127.0.0.1:8765")
    log_level: str = Field(default="INFO")
    log_dir: Path = Field(default=Path("/var/log/devbox-bridge"))

    @field_validator("bind")
    @classmethod
    def _validate_bind(cls, v: str) -> str:
        m = re.fullmatch(r"(?P<host>[^:]+):(?P<port>\d+)", v)
        if not m or not (1 <= int(m["port"]) <= 65535):
            raise ValueError(f"server.bind '{v}' non è host:port valido")
        return v

    @field_validator("log_level")
    @classmethod
    def _validate_log_level(cls, v: str) -> str:
        allowed = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        if v.upper() not in allowed:
            raise ValueError(f"server.log_level '{v}' non in {sorted(allowed)}")
        return v.upper()

    @field_validator("log_dir")
    @classmethod
    def _log_dir_absolute(cls, v: Path) -> Path:
        return _require_absolute(v, "server.log_dir")


class AuthConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    token_hash_file: Path


class AuditConfig(BaseModel):
    """Config audit log. Tutti i campi opzionali con default sensati: il
    blocco `audit:` può essere completamente omesso da config.yaml."""

    model_config = ConfigDict(extra="forbid")

    log_dir: Path | None = None  # default: <server.log_dir>/audit
    rotation_size_mb: int = Field(default=50, ge=1, le=10_000)
    retention_days: int = Field(default=90, ge=1, le=3650)
    audit_reads: bool = False

    @field_validator("log_dir")
    @classmethod
    def _log_dir_absolute(cls, v: Path | None) -> Path | None:
        if v is None:
            return None
        return _require_absolute(v, "audit.log_dir")


class ProjectConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: Path
    write_enabled: bool = False
    allow_push: bool = False
    test_command: str | None = None
    lint_command: str | None = None
    build_command: str | None = None
    command_whitelist: list[str] = Field(default_factory=list)
    env_passthrough: list[str] = Field(default_factory=list)
    # Override per progetto del limite di read inline. None → default 10MB nel
    # tool. Ceiling 50MB: oltre questa soglia il content nel JSON response MCP
    # satura il context window di qualunque client (vedi HANDOFF.md).
    max_read_bytes: int | None = Field(default=None, ge=1024, le=50 * 1024 * 1024)

    @field_validator("path")
    @classmethod
    def _path_absolute(cls, v: Path) -> Path:
        return _require_absolute(v, "projects[].path")

    @field_validator("command_whitelist")
    @classmethod
    def _whitelist_is_compilable(cls, v: list[str]) -> list[str]:
        for pattern in v:
            try:
                re.compile(pattern)
            except re.error as e:
                raise ValueError(f"pattern whitelist '{pattern}' non compila: {e}") from e
        return v

    @field_validator("env_passthrough")
    @classmethod
    def _env_names_valid(cls, v: list[str]) -> list[str]:
        for name in v:
            if not re.fullmatch(r"[A-Z_][A-Z0-9_]*", name):
                raise ValueError(
                    f"env_passthrough '{name}' non è un nome variabile env valido "
                    "(maiuscolo, underscore, no minuscole)"
                )
        return v

    @model_validator(mode="after")
    def _allow_push_requires_write(self) -> ProjectConfig:
        if self.allow_push and not self.write_enabled:
            raise ValueError(
                "allow_push=true richiede write_enabled=true "
                "(non puoi pushare senza poter scrivere)"
            )
        return self


# Default sensati per SystemConfig — single source of truth: NON duplicare
# in tools/system.py. Cambia qui se devi cambiare il default permissivo.
# Semantica fail-secure: questi default si applicano SOLO se l'utente ha
# omesso interamente la sezione `system:` (o l'ha lasciata `system: {}`).
# Una whitelist esplicitamente vuota in YAML (`log_paths_whitelist: []`) NON
# riceve i default — viene rispettata come "nessun path accessibile".
DEFAULT_LOG_PATHS_WHITELIST: tuple[Path, ...] = (Path("/var/log/devbox-bridge"),)
DEFAULT_SYSTEMD_UNIT_WHITELIST: tuple[str, ...] = ("devbox-bridge.service",)
DEFAULT_SYSTEMD_FILTER: str = "devbox-"

# Regex per nomi unit systemd. Vale anche per il filter di list_systemd_services
# (che è un substring sul nome unit, quindi ha lo stesso alfabeto ammesso).
# Caratteri ammessi: alfanumerico, `_`, `-`, `.`, `@`, `:`. Range conservativo,
# nessun whitespace o shell metachar.
_SYSTEMD_NAME_RE = re.compile(r"^[A-Za-z0-9._@:-]{1,64}$")


class SystemConfig(BaseModel):
    """Whitelist per i tool read-only di sistema (tools/system.py).

    Comportamento "presente ma vuoto":
      - sezione `system:` interamente omessa → default permissivo
        (DEFAULT_LOG_PATHS_WHITELIST, DEFAULT_SYSTEMD_UNIT_WHITELIST).
      - sezione `system:` presente con whitelist esplicitamente `[]` →
        fail-secure (zero path/unit accessibili). Scelta deliberata
        dell'operatore = rispettata letteralmente.

    Distinzione esplicita: i default permissivi sono onboarding-friendly
    ma una whitelist svuotata è una decisione di sicurezza dell'operatore.
    Il default che riempie automaticamente una lista vuota sarebbe
    fail-open — anti-pattern.
    """

    model_config = ConfigDict(extra="forbid")

    log_paths_whitelist: list[Path] = Field(
        default_factory=lambda: list(DEFAULT_LOG_PATHS_WHITELIST)
    )
    systemd_unit_whitelist: list[str] = Field(
        default_factory=lambda: list(DEFAULT_SYSTEMD_UNIT_WHITELIST)
    )
    systemd_filter_default: str = Field(default=DEFAULT_SYSTEMD_FILTER)

    @field_validator("log_paths_whitelist")
    @classmethod
    def _log_paths_absolute(cls, v: list[Path]) -> list[Path]:
        out: list[Path] = []
        for i, p in enumerate(v):
            out.append(_require_absolute(p, f"system.log_paths_whitelist[{i}]"))
        return out

    @field_validator("systemd_unit_whitelist")
    @classmethod
    def _unit_names_valid(cls, v: list[str]) -> list[str]:
        for name in v:
            if not _SYSTEMD_NAME_RE.fullmatch(name):
                raise ValueError(
                    f"system.systemd_unit_whitelist '{name}' non è un nome unit valido"
                )
        return v

    @field_validator("systemd_filter_default")
    @classmethod
    def _filter_default_valid(cls, v: str) -> str:
        # Stringa vuota = "nessun filtro" → ammessa.
        if v == "":
            return v
        if not _SYSTEMD_NAME_RE.fullmatch(v):
            raise ValueError(
                f"system.systemd_filter_default '{v}' non è un pattern valido"
            )
        return v


class AppConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    server: ServerConfig = Field(default_factory=ServerConfig)
    auth: AuthConfig
    audit: AuditConfig = Field(default_factory=AuditConfig)
    system: SystemConfig = Field(default_factory=SystemConfig)
    projects: dict[ProjectName, ProjectConfig] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _projects_have_unique_paths(self) -> AppConfig:
        seen: dict[str, str] = {}
        for name, proj in self.projects.items():
            key = str(proj.path)
            if key in seen:
                raise ValueError(
                    f"projects '{name}' e '{seen[key]}' puntano allo stesso path '{key}'"
                )
            seen[key] = name
        return self

    def project(self, name: str) -> ProjectConfig:
        try:
            return self.projects[name]
        except KeyError as e:
            raise ConfigError(f"progetto '{name}' non in config") from e


def load_config(path: str | Path) -> AppConfig:
    """Carica e valida il file YAML di config.

    Errori sollevati come ConfigError con messaggio leggibile.
    """
    p = Path(path)
    if not p.is_file():
        raise ConfigError(f"config file '{p}' non trovato")
    try:
        raw = yaml.safe_load(p.read_text(encoding="utf-8"))
    except yaml.YAMLError as e:
        raise ConfigError(f"YAML non valido in '{p}': {e}") from e
    if raw is None:
        raise ConfigError(f"config file '{p}' è vuoto")
    if not isinstance(raw, dict):
        raise ConfigError(
            f"config file '{p}' deve avere un dict alla root, ho '{type(raw).__name__}'"
        )
    try:
        return AppConfig.model_validate(raw)
    except Exception as e:
        raise ConfigError(f"validazione fallita per '{p}': {e}") from e
