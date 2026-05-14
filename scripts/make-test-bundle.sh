#!/usr/bin/env bash
# make-test-bundle.sh — fabbrica un bundle valido per register-project.sh,
# usato per:
#   (a) testare register-project.sh prima che il tool bridge-side T0.1 esista;
#   (b) servire da reference implementation di cosa il tool `prepare_project_bundle`
#       dovrà produrre lato bridge (stesso schema, stessa HMAC, stesso sha256_tree).
#
# Uso:
#   sudo -u devbox-bridge ./scripts/make-test-bundle.sh <name> <source_dir> [--ro]
#
#   <name>        : nome progetto, regex ^[a-z0-9][a-z0-9-]{1,39}$
#   <source_dir>  : directory locale che diventerà payload/. Viene COPIATA
#                   (no symlink). Esclude .git/.venv/__pycache__/node_modules
#                   per evitare bundle giganti — pulisci tu il source se vuoi
#                   filtri diversi.
#   --rw          : write_enabled=true nel config_block. DEFAULT è false
#                   (fail-secure, coerente col threat model "opt-in").
#   --ro          : esplicito, è già il default.
#
# Output: stampa su stdout il `manifest_id` da passare a register-project.sh:
#
#   sudo /opt/devbox-bridge/deploy/register-project.sh <manifest_id>
#
# Requisiti:
#   - Lo script deve girare COME utente `devbox-bridge` (la staging dir è
#     bridge:bridge 0750). Usa sudo -u devbox-bridge.
#   - install.sh deve essere già stato eseguito (servono staging dir + bootstrap.key).
#
# Test stand-alone consigliato:
#   mkdir -p /tmp/fake-delphi && echo "print('hi')" > /tmp/fake-delphi/app.py
#   MID=$(sudo -u devbox-bridge ./scripts/make-test-bundle.sh fake-delphi /tmp/fake-delphi)
#   sudo /opt/devbox-bridge/deploy/register-project.sh $MID

set -euo pipefail
IFS=$'\n\t'

readonly CONFIG_DIR="/etc/devbox-bridge"
readonly BOOTSTRAP_KEY="${CONFIG_DIR}/bootstrap.key"
readonly STAGING_ROOT="/var/lib/devbox-bridge/staging"
readonly PROJECTS_ROOT="/home/hypn0/projects"
readonly NAME_RE='^[a-z0-9][a-z0-9-]{0,38}[a-z0-9]$'

log()  { printf '\033[1;34m[make-bundle]\033[0m %s\n' "$*" >&2; }
fail() { printf '\033[1;31m[make-bundle]\033[0m %s\n' "$*" >&2; exit 1; }

# --- 1. Args + pre-flight -------------------------------------------------

# Default fail-secure: write_enabled=false. Per testare il path rw passare --rw.
WRITE_ENABLED=false
POSITIONAL=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --ro)
            WRITE_ENABLED=false
            shift
            ;;
        --rw)
            WRITE_ENABLED=true
            shift
            ;;
        -h|--help)
            sed -n '2,30p' "${BASH_SOURCE[0]}" | sed 's/^# \?//'
            exit 0
            ;;
        -*)
            fail "flag non riconosciuta: $1"
            ;;
        *)
            POSITIONAL+=("$1")
            shift
            ;;
    esac
done

[[ ${#POSITIONAL[@]} -eq 2 ]] || fail "uso: $0 <name> <source_dir> [--ro]"
NAME="${POSITIONAL[0]}"
SOURCE_DIR="${POSITIONAL[1]}"

[[ "${NAME}" =~ ${NAME_RE} ]] \
    || fail "name '${NAME}' non valido (regex ${NAME_RE})"
[[ -d "${SOURCE_DIR}" ]] \
    || fail "source_dir non è una directory: ${SOURCE_DIR}"
[[ -r "${BOOTSTRAP_KEY}" ]] \
    || fail "bootstrap.key non leggibile da $(id -un): ${BOOTSTRAP_KEY} (lancia con sudo -u devbox-bridge)"
[[ -d "${STAGING_ROOT}" ]] \
    || fail "staging root non esiste: ${STAGING_ROOT} (esegui install.sh)"
[[ -w "${STAGING_ROOT}" ]] \
    || fail "staging root non scrivibile da $(id -un): ${STAGING_ROOT}"
command -v python3 > /dev/null || fail "python3 non trovato"

# Verifica che il progetto non sia già registrato — register-project.sh
# rifiuterebbe per safety, ma è meglio fallire qui prima di copiare tutto.
TARGET_PATH="${PROJECTS_ROOT}/${NAME}"
if [[ -e "${TARGET_PATH}" ]]; then
    fail "${TARGET_PATH} esiste già — usa un nome diverso, o cancellalo a mano (con sudo) se è leftover di un test precedente"
fi

# --- 2. Genera manifest_id e crea staging bundle dir ----------------------

MANIFEST_ID="$(openssl rand -hex 16)"
BUNDLE_DIR="${STAGING_ROOT}/${MANIFEST_ID}"
PAYLOAD_DIR="${BUNDLE_DIR}/payload"

log "manifest_id: ${MANIFEST_ID}"
log "bundle dir:  ${BUNDLE_DIR}"

mkdir -m 0750 "${BUNDLE_DIR}"
mkdir -m 0750 "${PAYLOAD_DIR}"

# Cleanup su errore
trap 'rm -rf "${BUNDLE_DIR}"' ERR

# --- 3. Copia source → payload (no symlink, esclude noise) ---------------

log "copio ${SOURCE_DIR} → ${PAYLOAD_DIR} (escludo .git/.venv/__pycache__/node_modules)"
# rsync -aH SENZA -l (NO symlink): se ci sono symlink nel source, vengono
# saltati. Più sicuro di cp -r che li copierebbe come tali.
rsync -a --no-links --no-perms --chmod=Du=rwx,Dgo=rx,Fu=rw,Fgo=r \
      --exclude='.git/' --exclude='.venv/' --exclude='__pycache__/' \
      --exclude='node_modules/' --exclude='.pytest_cache/' \
      --exclude='.mypy_cache/' --exclude='.ruff_cache/' \
      "${SOURCE_DIR}/" "${PAYLOAD_DIR}/"

# Sanity: no symlink trapelato (rsync --no-links li ignora, ma double-check)
if find "${PAYLOAD_DIR}" -type l | grep -q .; then
    fail "symlink trovato nel payload dopo rsync — rifiutato"
fi

# --- 4. Costruzione manifest + sha256_tree + HMAC (Python embedded) ------
#
# Bit-identica all'algoritmo di register-project.sh:
#   sha256_tree = sha256 di concatenazione di {rel_path}\0{file_sha256}\n
#                 per file ordinati per rel_path.

log "calcolo sha256_tree e firmo manifest"
python3 - "${BUNDLE_DIR}" "${PAYLOAD_DIR}" "${BOOTSTRAP_KEY}" \
          "${NAME}" "${TARGET_PATH}" "${WRITE_ENABLED}" "${MANIFEST_ID}" <<'PYEOF'
import hashlib
import hmac
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

bundle_dir, payload_dir, key_path, name, target_path, write_enabled_s, manifest_id = sys.argv[1:8]
write_enabled = (write_enabled_s == "true")

# sha256_tree (stesso algoritmo di register-project.sh)
payload = Path(payload_dir)
tree_hasher = hashlib.sha256()
file_count = 0
total_bytes = 0
for root, dirs, files in os.walk(payload, followlinks=False):
    dirs.sort()
    files.sort()
    for fn in files:
        fp = Path(root) / fn
        if fp.is_symlink():
            raise SystemExit(f"symlink interno: {fp}")
        rel = fp.relative_to(payload).as_posix()
        h = hashlib.sha256()
        with fp.open("rb") as f:
            while True:
                chunk = f.read(1 << 20)
                if not chunk:
                    break
                h.update(chunk)
                total_bytes += len(chunk)
        tree_hasher.update(rel.encode("utf-8") + b"\0" + h.hexdigest().encode("ascii") + b"\n")
        file_count += 1

sha256_tree = tree_hasher.hexdigest()

# config_block: defaults sensati. Editabili a mano nel manifest se vuoi
# testare write_enabled=false, test_command custom, ecc.
config_block = {
    "path": target_path,
    "write_enabled": write_enabled,
    "allow_push": False,
    "test_command": "pytest -x --tb=short",
    "lint_command": "ruff check .",
    "build_command": None,
    "command_whitelist": [
        "^pytest( .*)?$",
        "^ruff( .*)?$",
        "^mypy( .*)?$",
    ],
    "env_passthrough": [],
}

ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")

manifest = {
    "version": 1,
    "manifest_id": manifest_id,
    "name": name,
    "path_target": target_path,
    "sha256_tree": sha256_tree,
    "config_block": config_block,
    "ts": ts,
    "created_by": "make-test-bundle.sh",
}

# Serialize DETERMINISTICALLY (sort_keys + no whitespace variance) per HMAC
# riproducibile bit-a-bit. register-project.sh fa HMAC sui BYTES del file
# letti tali e quali, quindi qui dobbiamo scrivere ESATTAMENTE quei bytes.
manifest_bytes = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")

# Firma HMAC-SHA256
key = Path(key_path).read_bytes().strip()
sig = hmac.new(key, manifest_bytes, hashlib.sha256).hexdigest()

# Scrivi i due file con i permessi giusti (la bundle dir è 0750 bridge:bridge)
bundle = Path(bundle_dir)
(bundle / "manifest.json").write_bytes(manifest_bytes)
(bundle / "manifest.hmac").write_text(sig + "\n")

# File mode 0640 per essere coerenti col resto del bridge state
(bundle / "manifest.json").chmod(0o640)
(bundle / "manifest.hmac").chmod(0o640)

print(f"files={file_count}", file=sys.stderr)
print(f"bytes={total_bytes}", file=sys.stderr)
print(f"sha256_tree={sha256_tree}", file=sys.stderr)
PYEOF

# --- 5. Output ------------------------------------------------------------

# Disabilita il trap di cleanup ora che il bundle è completo
trap - ERR

log "bundle pronto in ${BUNDLE_DIR}"
log "lancia ora come root:"
log "  sudo /opt/devbox-bridge/deploy/register-project.sh ${MANIFEST_ID}"
log ""

# Stampa solo il manifest_id su stdout così è catturabile con $(...)
echo "${MANIFEST_ID}"
