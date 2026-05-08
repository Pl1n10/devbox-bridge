"""Path traversal guard.

Ogni accesso a filesystem dei tool MCP DEVE passare per resolve_project_path()
o resolve_within(). Questi sono gli unici due punti di ingresso autorizzati.

Threat model:
  - Path traversal classico: '..', '../../etc/passwd'
  - Path assoluti maliziosi: '/etc/passwd' come arg di read_file
  - Symlink che escono: <progetto>/link → /etc → traversal silenzioso

Limiti noti:
  - Mount point bind: out of scope (assumiamo che il filesystem sotto il
    progetto non contenga symlink/bind che il sysadmin non abbia autorizzato).
  - TOCTOU (time-of-check vs time-of-use): tra il resolve_within() e l'uso
    effettivo del path da parte del tool chiamante (open, mkdir, ecc.) c'è
    una finestra in cui un symlink può essere creato/modificato per
    redirigere altrove. Esempio: resolve_within ritorna <root>/foo/bar.txt
    con `foo` non esistente; tra il return e la open() un attaccante crea
    `foo` come symlink a /tmp → la write finisce in /tmp/bar.txt.
    Mitigazione completa richiederebbe openat() con RESOLVE_BENEATH
    (Linux 5.6+) o equivalente. Trattato come accettabile per il threat
    model attuale perché:
      - Il filesystem dei progetti è single-tenant (utente hypn0).
      - Nessun altro utente non-root può creare symlink dentro i progetti.
      - I subprocess dei tool sono lanciati con env sanitizzato (niente
        LD_PRELOAD/LD_LIBRARY_PATH).
"""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

from devbox_bridge.config import AppConfig


class PathSecurityError(ValueError):
    """Tentativo di accedere a un path fuori dalla whitelist progetti."""


def resolve_within(project_root: Path, candidate: str | Path) -> Path:
    """Risolve `candidate` (relativo a project_root o assoluto) e verifica che
    cada DENTRO project_root. Solleva PathSecurityError altrimenti.

    Implementazione:
      - project_root viene .resolve(strict=True) → segue symlink, fallisce se
        la directory non esiste (vogliamo questo: errore esplicito).
      - candidate, se relativo, viene joinato a project_root PRIMA del resolve.
      - Il resolve segue tutti i symlink esistenti → simulazioni
        '<proj>/link → /etc' vengono rilevate e bloccate.
      - Verifica via relative_to() con try/except per messaggio chiaro.
    """
    try:
        root_resolved = Path(project_root).resolve(strict=True)
    except FileNotFoundError as e:
        raise PathSecurityError(
            f"project_root '{project_root}' non esiste o non è accessibile"
        ) from e

    cand = Path(candidate)
    if cand.is_absolute():
        target = cand
    else:
        target = root_resolved / cand

    # strict=False: non richiediamo che il file di destinazione esista
    # (write_file su nuovo file). Symlink intermedi che esistono vengono
    # comunque seguiti e validati dal resolve.
    target_resolved = target.resolve(strict=False)

    try:
        target_resolved.relative_to(root_resolved)
    except ValueError as e:
        raise PathSecurityError(
            f"path '{candidate}' esce dalla project root '{project_root}' "
            f"(risolto a '{target_resolved}')"
        ) from e

    return target_resolved


def resolve_project_path(config: AppConfig, project: str, path: str | Path) -> Path:
    """Convenience: prende il root dal config e applica resolve_within.

    Solleva ConfigError se il progetto non esiste in config; PathSecurityError
    se il path esce dal root.
    """
    proj = config.project(project)
    return resolve_within(proj.path, path)


def resolve_within_any(
    candidate: str | Path,
    allowed_roots: Iterable[Path],
) -> Path:
    """Risolve `candidate` (assoluto) e verifica che cada DENTRO almeno uno
    dei root in `allowed_roots`. Usata da tools/system.tail_log per validare
    path assoluti contro una whitelist di directory.

    Differenze con resolve_within():
      - candidate DEVE essere assoluto (PathSecurityError altrimenti).
      - L'ordine di validazione è: whitelist PRIMA, esistenza DOPO. Quindi
        un path fuori whitelist solleva PathSecurityError anche se non
        esiste, evitando un info-leak debole ("path X non esiste" vs
        "path X fuori whitelist" → discriminerebbe l'esistenza di file
        fuori whitelist).
      - Se candidato è dentro la whitelist ma non esiste, propaga
        FileNotFoundError: il chiamante distingue "log non autorizzato"
        (PathSecurityError) da "log autorizzato ma non presente"
        (FileNotFoundError → mappato di solito su LogPathNotFoundError).
      - L'ordine di allowed_roots NON è semanticamente significativo: il
        path è valido se cade in almeno un root, indipendentemente dalla
        posizione nella lista. "Primo match vince" è dettaglio
        implementativo (early return per efficienza). Sovrapposizioni di
        root (es. /var/log e /var/log/devbox-bridge) restano consistenti.
      - Symlink: doppio check.
          (a) Pre-esistenza: cand.resolve(strict=False) normalizza '..' e
              segue i symlink intermedi che ESISTONO. Un symlink che esce
              dalla whitelist viene rilevato qui.
          (b) Post-esistenza: cand.resolve(strict=True) viene rifatto sul
              path effettivamente esistente; viene re-validato contro la
              whitelist (defense-in-depth contro race condition / symlink
              sostituiti tra il check (a) e l'open() del subprocess —
              non chiude la finestra TOCTOU completamente, ma riduce la
              superficie).

    Roots inesistenti vengono SALTATI silenziosamente (non sollevano):
    rendere la whitelist robusta a un mountpoint smontato è preferibile a
    rompere tutti i tool quando un singolo root non è più disponibile.
    """
    cand = Path(candidate)
    if not cand.is_absolute():
        raise PathSecurityError(
            f"path '{candidate}' deve essere assoluto"
        )

    # Materializza i root resolved una volta sola per riuso nei due check.
    roots_resolved: list[Path] = []
    for root in allowed_roots:
        try:
            roots_resolved.append(Path(root).resolve(strict=True))
        except FileNotFoundError:
            continue

    # (a) Check whitelist con resolve non-strict. Normalizza '..' e segue
    #     symlink intermedi esistenti; non solleva su path finale inesistente.
    target_normalized = cand.resolve(strict=False)
    if not _is_under_any(target_normalized, roots_resolved):
        raise PathSecurityError(
            f"path '{candidate}' (risolto a '{target_normalized}') non è "
            f"dentro alcuna whitelist root"
        )

    # Verifica esistenza solo dopo aver passato la whitelist: chi chiama
    # con un path fuori whitelist non scopre se un altro file esiste
    # nel sistema.
    target_strict = cand.resolve(strict=True)  # propaga FileNotFoundError

    # (b) Re-validate post-strict-resolve. Se un symlink finale punta
    #     fuori dalla whitelist, qui lo blocchiamo.
    if not _is_under_any(target_strict, roots_resolved):
        raise PathSecurityError(
            f"path '{candidate}' (risolto a '{target_strict}') esce dalla "
            f"whitelist dopo risoluzione symlink"
        )

    return target_strict


def _is_under_any(target: Path, roots: list[Path]) -> bool:
    for root in roots:
        try:
            target.relative_to(root)
            return True
        except ValueError:
            continue
    return False
