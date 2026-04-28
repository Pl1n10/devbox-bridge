"""Sanitizer dell'environment passato ai subprocess.

Filosofia: whitelist mode. Si parte da {} e si aggiungono solo:
  - Variabili "infrastrutturali" (PATH, HOME, LANG, LC_*, ...) che servono al
    subprocess per funzionare e non sono secret.
  - Variabili in `passthrough` (config per-progetto: env_passthrough).

Tutto il resto viene droppato — anche se non matcha nessun secret pattern noto.
Questo protegge da export "accidentali" di secret in shell che non rispettano
le naming convention standard.

`_SECRET_PATTERNS` è usato solo come "warning system" per audit: se un nome in
passthrough matcha un secret pattern, viene loggato un warning
`env.passthrough.secret_match`. Il passthrough resta valido — il warning serve
solo a tracciare l'uso di una deroga.
"""

from __future__ import annotations

import os
import re
from collections.abc import Iterable, Mapping

import structlog

logger = structlog.get_logger("devbox_bridge.security.env")

# Pattern che identificano variabili sensibili. Usati per warning log su
# passthrough deroghe; NON usati come deny list (la deny è implicita nel
# whitelist mode).
_SECRET_PATTERNS = [
    re.compile(r"^AWS_.*$"),
    re.compile(r".*_TOKEN$"),
    re.compile(r".*_SECRET$"),
    re.compile(r".*_KEY$"),
    re.compile(r".*_PASSWORD$"),
    re.compile(r".*_PASS$"),
    re.compile(r"^OPENAI_API_KEY$"),
    re.compile(r"^ANTHROPIC_API_KEY$"),
    re.compile(r"^OPENROUTER_API_KEY$"),
]

# Variabili infra esplicite. SEMPRE preservate da parent_env se presenti.
_INFRA_VARS = frozenset({
    "PATH",
    "HOME",
    "USER",
    "LOGNAME",
    "SHELL",
    "LANG",
    "TZ",
    "TMPDIR",
    "TERM",
})

# LC_* completo (POSIX): LC_ALL, LC_CTYPE, LC_TIME, LC_NUMERIC, LC_MESSAGES,
# LC_MONETARY, LC_COLLATE, LC_PAPER, LC_NAME, LC_ADDRESS, LC_TELEPHONE,
# LC_MEASUREMENT, LC_IDENTIFICATION e qualsiasi futura LC_*.
_INFRA_PATTERNS = [re.compile(r"^LC_[A-Z][A-Z_]*$")]


def _is_secret(name: str) -> bool:
    return any(p.fullmatch(name) for p in _SECRET_PATTERNS)


def _is_infra(name: str) -> bool:
    return name in _INFRA_VARS or any(p.fullmatch(name) for p in _INFRA_PATTERNS)


def sanitize_env(
    parent_env: Mapping[str, str],
    passthrough: Iterable[str] = (),
) -> dict[str, str]:
    """Costruisce un env per subprocess partendo da parent_env, mantenendo solo
    variabili infra + il passthrough esplicito.

    Algoritmo:
      1. Parti da {} (whitelist mode).
      2. Aggiungi tutte le variabili di parent_env che sono _is_infra().
      3. Per ogni nome in passthrough presente in parent_env:
         - se matcha un secret pattern → logga warning per audit
         - copia il valore (override esplicito vince sulla whitelist policy)
      4. Niente altro.
    """
    out: dict[str, str] = {}

    for var, val in parent_env.items():
        if _is_infra(var):
            out[var] = val

    for var in passthrough:
        if var in parent_env:
            if _is_secret(var):
                logger.warning("env.passthrough.secret_match", var=var)
            out[var] = parent_env[var]

    return out


def get_current_env() -> Mapping[str, str]:
    """Helper per i tool: ritorna os.environ come Mapping."""
    return os.environ
