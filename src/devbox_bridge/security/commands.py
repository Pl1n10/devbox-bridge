"""Command whitelist (per progetto) + deny list hardcoded.

Strategia di validazione (vedi docs/SECURITY.md "Strategia deny list"):

  1. shlex.split: il comando deve essere parsabile (quoting bilanciato).
  2. Deny list:
     a) Tokenize-and-check su comandi multi-argomento (rm, chown, chmod,
        dd, mv, kill). Ispeziona argv per individuare flag ricorsivi e
        path "broad" indipendentemente dalla loro posizione nella stringa.
        Questo è il modo CORRETTO di gestire comandi come `rm -rf /` —
        un singolo regex su stringa intera ha bypass triviali (es.
        `rm -rf / --verbose` o `rm -rf / /tmp/x`).
     b) Regex monolitica search per costrutti sintatticamente fissi:
        fork bomb, curl|sh, redirect a /etc, shutdown/reboot, ecc.
  3. Whitelist (per progetto): re.fullmatch su almeno un pattern. Senza
     whitelist o senza match → reject.

Note:
  - re.fullmatch sulla whitelist (anchor implicito): impedisce che
    `pytest && rm -rf /` matchi un pattern `pytest`.
  - re.search sulla deny list: cattura il pattern ovunque appaia.
  - Alcuni pattern regex (curl|sh, redirect a path) sono RIDONDANTI con
    `subprocess.run(shell=False)` (le metachar diventano arg letterali).
    Tenuti come defense-in-depth contro futuri regression che
    reintroducano `shell=True`.
  - subprocess.run con shell=True è BANDITO ovunque nel codebase.
"""

from __future__ import annotations

import re
import shlex


class CommandRejectedError(ValueError):
    """Comando bloccato (deny list, syntax invalida, o non in whitelist)."""


# Path "broad" dove operazioni ricorsive distruttive sono sempre bloccate.
_DANGER_PATHS: frozenset[str] = frozenset({
    "/",
    "~",
    "$HOME",
    "/home",
    "/etc",
    "/usr",
    "/var",
    "/boot",
    "/root",
    "/sys",
    "/proc",
    "/dev",
    "/lib",
    "/lib64",
    "/sbin",
    "/bin",
    "/opt",
})

# Prefissi path di sistema usati da dd of= e da redirect (>) check.
_DANGER_PATH_PREFIXES: tuple[str, ...] = (
    "/dev/",
    "/etc/",
    "/boot/",
    "/usr/",
    "/var/",
    "/root/",
    "/sys/",
    "/proc/",
    "/lib/",
    "/lib64/",
    "/sbin/",
    "/bin/",
    "/opt/",
)


def _arg_is_danger_path(arg: str) -> bool:
    """True se arg è un path di sistema (con o senza trailing slash)."""
    if arg in _DANGER_PATHS:
        return True
    stripped = arg.rstrip("/")
    return stripped in _DANGER_PATHS and stripped != ""


def _has_recursive_flag(argv: list[str], short_letters: str = "rR") -> bool:
    """True se argv contiene un flag ricorsivo (-r, -R, --recursive, -rf, ecc.)."""
    long_flag = "--recursive"
    short_explicit = {f"-{c}" for c in short_letters}
    for arg in argv:
        if arg == long_flag or arg in short_explicit:
            return True
        # Flag corti combinati: -rf, -fr, -Rfv, ecc.
        if (
            arg.startswith("-")
            and not arg.startswith("--")
            and len(arg) >= 2
            and any(c in arg[1:] for c in short_letters)
        ):
            return True
    return False


def _check_dangerous_rm(argv: list[str]) -> None:
    if not argv or argv[0] != "rm":
        return
    if "--no-preserve-root" in argv:
        raise CommandRejectedError("rm --no-preserve-root bloccato dalla deny list")
    if not _has_recursive_flag(argv[1:], short_letters="rR"):
        return
    for arg in argv[1:]:
        if _arg_is_danger_path(arg):
            raise CommandRejectedError(
                f"rm -r su path di sistema '{arg}' bloccato dalla deny list"
            )


def _check_dangerous_chown_chmod(argv: list[str]) -> None:
    if not argv or argv[0] not in {"chown", "chmod"}:
        return
    if not _has_recursive_flag(argv[1:], short_letters="R"):
        return
    for arg in argv[1:]:
        if _arg_is_danger_path(arg):
            raise CommandRejectedError(
                f"{argv[0]} -R su path di sistema '{arg}' bloccato dalla deny list"
            )


def _check_dangerous_dd(argv: list[str]) -> None:
    if not argv or argv[0] != "dd":
        return
    for arg in argv[1:]:
        if not arg.startswith("of="):
            continue
        target = arg[3:]
        if target == "/" or target.startswith(_DANGER_PATH_PREFIXES):
            raise CommandRejectedError(
                f"dd of='{target}' su path di sistema bloccato dalla deny list"
            )


def _check_dangerous_mv(argv: list[str]) -> None:
    if not argv or argv[0] != "mv":
        return
    for arg in argv[1:]:
        if arg.startswith("-"):
            continue
        if _arg_is_danger_path(arg):
            raise CommandRejectedError(
                f"mv con path di sistema '{arg}' bloccato dalla deny list"
            )
        if arg == "/dev/null":
            raise CommandRejectedError(
                "mv su /dev/null distrugge i dati, bloccato dalla deny list"
            )


def _check_dangerous_kill_init(argv: list[str]) -> None:
    if not argv or argv[0] != "kill":
        return
    for arg in argv[1:]:
        if arg.startswith("-"):
            continue
        if arg == "1":
            raise CommandRejectedError(
                "kill PID 1 (init/systemd) bloccato dalla deny list"
            )


def _check_dangerous_mkfs(argv: list[str]) -> None:
    if not argv or not argv[0].startswith("mkfs"):
        return
    # mkfs su QUALSIASI argomento che inizia con /dev/ o è un device.
    for arg in argv[1:]:
        if arg.startswith("/dev/"):
            raise CommandRejectedError(
                f"mkfs su device '{arg}' bloccato dalla deny list"
            )


# Pattern regex per costrutti sintatticamente fissi. re.search → cattura
# il pattern ovunque appaia nella stringa.
_DENY_REGEX: list[tuple[re.Pattern[str], str]] = [
    # Fork bomb classica.
    (
        re.compile(r":\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:"),
        "fork bomb",
    ),
    # Download piped a interprete. Ridondante con shell=False (la pipe
    # diventa arg letterale di curl), tenuto come defense-in-depth.
    (
        re.compile(
            r"\b(curl|wget|fetch)\b.*\|\s*"
            r"(sh|bash|zsh|ksh|dash|python3?|perl|ruby|node)\b"
        ),
        "download piped a interprete",
    ),
    # Redirect verso path di sistema. Ridondante con shell=False
    # (> diventa arg letterale), defense-in-depth.
    (
        re.compile(r">\s*/(dev|etc|boot|usr|var|root|sys|proc|lib|lib64|sbin|bin|opt)/"),
        "redirect a path di sistema",
    ),
    # Power management.
    (
        re.compile(r"^\s*(shutdown|reboot|poweroff|halt)\b"),
        "power management",
    ),
    (
        re.compile(r"^\s*init\s+[06]\s*$"),
        "init runlevel 0/6",
    ),
    (
        re.compile(r"^\s*systemctl\s+(poweroff|reboot|halt|emergency|rescue)\b"),
        "systemctl power/runlevel",
    ),
]


def _check_deny_regex(command: str) -> None:
    for pattern, label in _DENY_REGEX:
        if pattern.search(command):
            raise CommandRejectedError(
                f"comando bloccato dalla deny list ({label})"
            )


def _check_deny_tokenize(argv: list[str]) -> None:
    _check_dangerous_rm(argv)
    _check_dangerous_chown_chmod(argv)
    _check_dangerous_dd(argv)
    _check_dangerous_mv(argv)
    _check_dangerous_kill_init(argv)
    _check_dangerous_mkfs(argv)


def _check_parseable(command: str) -> list[str]:
    """Verifica quoting bilanciato; ritorna argv tokenizzati."""
    try:
        return shlex.split(command, posix=True)
    except ValueError as e:
        raise CommandRejectedError(f"comando non parsabile: {e}") from e


def is_command_allowed(command: str, whitelist: list[str]) -> bool:
    """True se il comando passa deny list E matcha la whitelist. No-raise wrapper."""
    try:
        check_command(command, whitelist)
        return True
    except CommandRejectedError:
        return False


def check_deny_list(command: str) -> None:
    """Verifica SOLO la deny list (parse + tokenize + regex). Solleva
    CommandRejectedError se blocked.

    Esposta come funzione pubblica per i tool che eseguono comandi
    amministrativamente autorizzati (test/lint/build presi da config), per
    cui la whitelist regex è bypassata MA la deny list deve restare attiva
    (es. blocca per errore `pytest && rm -rf /` configurato in
    `test_command`).

    Ordine:
      1. shlex parseable
      2. deny list tokenize (rm/chown/chmod/dd/mv/kill/mkfs)
      3. deny list regex (fork bomb, curl|sh, redirect, power mgmt)
    """
    stripped = command.strip()
    if not stripped:
        raise CommandRejectedError("comando vuoto")

    argv = _check_parseable(stripped)
    _check_deny_tokenize(argv)
    _check_deny_regex(stripped)


def check_command(command: str, whitelist: list[str]) -> None:
    """Verifica completa: deny list + whitelist regex. Solleva
    CommandRejectedError se blocked.

    Usata per `run_command` (comando user-provided runtime). I 3 tool
    `run_tests`/`run_lint`/`run_build` chiamano invece `check_deny_list`
    direttamente (whitelist bypassata, vedi docstring lì).

    Ordine:
      1. check_deny_list (parse + tokenize + regex)
      2. whitelist regex fullmatch (almeno un pattern)
    """
    check_deny_list(command)
    stripped = command.strip()

    if not whitelist:
        raise CommandRejectedError(
            "nessuna whitelist configurata per questo progetto: "
            "tutti i comandi sono rifiutati"
        )

    for pattern in whitelist:
        try:
            if re.fullmatch(pattern, stripped):
                return
        except re.error:
            # Pattern non compilabile: bug di config (config.py lo prende già
            # al boot, ma difesa in profondità).
            continue

    raise CommandRejectedError(
        f"comando non matcha nessuna whitelist regex (whitelist: {len(whitelist)} pattern)"
    )
