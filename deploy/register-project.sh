#!/usr/bin/env bash
# register-project.sh — registratore root-side per progetti consegnati dal
# bridge come bundle staged. Fase 0 del roadmap "Bootstrap progetti da MCP"
# (vedi PM-MCP-PROJECT.md).
#
# Contratto Fase 0:
#   1. Il bridge (utente devbox-bridge) prepara un bundle in
#      /var/lib/devbox-bridge/staging/<manifest_id>/ con questa struttura:
#
#        <staging>/<manifest_id>/
#          manifest.json         # metadati (vedi schema sotto)
#          manifest.hmac         # HMAC-SHA256 di manifest.json (hex)
#          payload/              # albero file del progetto (no symlink interni)
#
#   2. Il bridge emette al chiamante (claude.ai) la stringa one-shot:
#        sudo /opt/devbox-bridge/deploy/register-project.sh <manifest_id>
#
#   3. L'operatore (Roberto) la incolla in shell root.
#
#   4. Questo script:
#        - valida il manifest_id (regex);
#        - verifica HMAC del manifest contro /etc/devbox-bridge/bootstrap.key;
#        - verifica timestamp non oltre N minuti (replay window);
#        - ricomputa sha256_tree del payload/ e confronta col manifest;
#        - valida path_target (jail in /home/hypn0/projects/, no symlink);
#        - sposta payload/ → /home/hypn0/projects/<name>/ (atomic mv same-fs);
#        - chown -R hypn0:hypn0 sul nuovo path (install.sh si aspetta owner hypn0);
#        - merge atomico del blocco progetto in /etc/devbox-bridge/config.yaml;
#        - richiama deploy/install.sh per applicare ACL + drop-in + daemon-reload;
#        - systemctl restart devbox-bridge.service (per ricaricare config);
#        - cleanup staging;
#        - scrive un evento JSON in /var/log/devbox-bridge/admin-audit.log.
#
# Schema manifest.json (v1):
#   {
#     "version": 1,
#     "manifest_id": "<hex 32+ char>",
#     "name": "<project-name>",
#     "path_target": "/home/hypn0/projects/<project-name>",
#     "sha256_tree": "<hex64>",
#     "config_block": { "path": "...", "write_enabled": bool, ... },
#     "ts": "<ISO8601 UTC con Z>",
#     "created_by": "devbox-bridge"
#   }
#
# Idempotenza: rieseguibile con lo stesso manifest_id. Se siamo a metà flow
# (mv già fatto, merge config già fatto, install.sh fallito): ogni step rileva
# il proprio "già fatto" e skippa, fino a completare. NO rollback automatico.
#
# Threat model:
#   - L'attaccante che può scrivere in /var/lib/devbox-bridge/staging/ (solo
#     bridge user) NON può forgiare un manifest: la bootstrap.key è
#     root:devbox-bridge 0640, leggibile dal bridge ma non scrivibile.
#     Senza la key, non passa l'HMAC.
#   - L'HMAC verifica è in Python con hmac.compare_digest (constant-time).
#   - Il replay è bloccato da TS window (default 10 min) + manifest_id
#     consumato all'inizio (rinominato in .consumed appena passa HMAC).
#   - L'estrazione dello zip lato bridge deve rifiutare path traversal e
#     symlink interni — questo script ASSUME quei check fatti, ma fa un
#     check finale "no symlink" sul payload/ prima di mv'are.

set -euo pipefail
IFS=$'\n\t'

# --- Costanti -------------------------------------------------------------

readonly SVC_USER="devbox-bridge"
readonly SVC_GROUP="devbox-bridge"
readonly CONFIG_DIR="/etc/devbox-bridge"
readonly CONFIG_FILE="${CONFIG_DIR}/config.yaml"
readonly BOOTSTRAP_KEY="${CONFIG_DIR}/bootstrap.key"
readonly STAGING_ROOT="/var/lib/devbox-bridge/staging"
readonly AUDIT_LOG="/var/log/devbox-bridge/admin-audit.log"
readonly UNIT_NAME="devbox-bridge.service"
readonly PROJECTS_ROOT="/home/hypn0/projects"
readonly OWNER_USER="hypn0"
readonly OWNER_GROUP="hypn0"
readonly REPLAY_WINDOW_MIN=10
readonly MANIFEST_ID_RE='^[a-f0-9]{32,64}$'

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
readonly SCRIPT_DIR
readonly INSTALL_SH="${SCRIPT_DIR}/install.sh"

log()  { printf '\033[1;34m[register]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[register]\033[0m %s\n' "$*" >&2; }
fail() { printf '\033[1;31m[register]\033[0m %s\n' "$*" >&2; audit_emit "error" "$*"; exit 1; }

# audit_emit: chiamato da fail() e dal flow finale. Best-effort, non vogliamo
# che un errore di audit blocchi un fix urgente. Schema simile a AuditLogger
# del bridge ma campi specifici per admin-side.
audit_emit() {
    local outcome="$1"
    local error_msg="${2:-}"
    local manifest_id="${MANIFEST_ID:-<unknown>}"
    local name="${MANIFEST_NAME:-<unknown>}"
    local path_target="${MANIFEST_PATH:-<unknown>}"
    local ts
    ts="$(date --utc +'%Y-%m-%dT%H:%M:%S.000Z')"
    install -d -m 0750 -o root -g "${SVC_GROUP}" "$(dirname "${AUDIT_LOG}")" 2>/dev/null || true
    {
        printf '{'
        printf '"timestamp":"%s",' "${ts}"
        printf '"event":"admin.register_project",'
        printf '"outcome":"%s",' "${outcome}"
        printf '"manifest_id":"%s",' "${manifest_id}"
        printf '"project_name":"%s",' "${name}"
        printf '"path_target":"%s",' "${path_target}"
        printf '"actor":"register-project.sh",'
        printf '"actor_pid":%d' "$$"
        if [[ -n "${error_msg}" ]]; then
            local esc
            esc="$(printf '%s' "${error_msg}" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))')"
            printf ',"error_message":%s' "${esc}"
        fi
        printf '}\n'
    } >> "${AUDIT_LOG}" 2>/dev/null || true
    chmod 0640 "${AUDIT_LOG}" 2>/dev/null || true
    chown root:"${SVC_GROUP}" "${AUDIT_LOG}" 2>/dev/null || true
}

# --- 1. Pre-flight --------------------------------------------------------

[[ ${EUID} -eq 0 ]]              || fail "deve girare come root (sudo $0 <manifest_id>)"
[[ -x "${INSTALL_SH}" ]]         || fail "install.sh non trovato/eseguibile: ${INSTALL_SH}"
[[ -f "${CONFIG_FILE}" ]]        || fail "config non trovato: ${CONFIG_FILE} — esegui install.sh prima"
[[ -f "${BOOTSTRAP_KEY}" ]]      || fail "bootstrap.key mancante: ${BOOTSTRAP_KEY} — esegui install.sh per generarla"
[[ -d "${STAGING_ROOT}" ]]       || fail "staging root mancante: ${STAGING_ROOT} — esegui install.sh per crearla"
[[ -d "${PROJECTS_ROOT}" ]]      || fail "projects root mancante: ${PROJECTS_ROOT}"
getent passwd "${SVC_USER}"      > /dev/null || fail "utente di servizio ${SVC_USER} non esiste"
getent passwd "${OWNER_USER}"    > /dev/null || fail "utente owner ${OWNER_USER} non esiste"
command -v python3               > /dev/null || fail "python3 non trovato nel PATH"

# --- 2. Argv: manifest_id -------------------------------------------------

[[ $# -eq 1 ]] || fail "uso: $0 <manifest_id>"
MANIFEST_ID="$1"
[[ "${MANIFEST_ID}" =~ ${MANIFEST_ID_RE} ]] \
    || fail "manifest_id malformato: '${MANIFEST_ID}' (atteso ${MANIFEST_ID_RE})"

readonly BUNDLE_DIR="${STAGING_ROOT}/${MANIFEST_ID}"
readonly MANIFEST_JSON="${BUNDLE_DIR}/manifest.json"
readonly MANIFEST_HMAC="${BUNDLE_DIR}/manifest.hmac"
readonly PAYLOAD_DIR="${BUNDLE_DIR}/payload"

[[ -d "${BUNDLE_DIR}" ]]         || fail "bundle non trovato: ${BUNDLE_DIR}"
[[ -f "${MANIFEST_JSON}" ]]      || fail "manifest.json mancante in ${BUNDLE_DIR}"
[[ -f "${MANIFEST_HMAC}" ]]      || fail "manifest.hmac mancante in ${BUNDLE_DIR}"
[[ -d "${PAYLOAD_DIR}" ]]        || fail "payload/ mancante in ${BUNDLE_DIR}"
[[ ! -L "${PAYLOAD_DIR}" ]]      || fail "payload/ è un symlink — rifiutato"

# --- 3. Verifica manifest (HMAC + schema + ts + sha256_tree) ---------------
#
# Tutto il lavoro non-banale è in Python: hmac.compare_digest (constant-time),
# json schema check, ts parsing, walk del payload per sha256_tree.
# Lo script bash riceve via stdout le variabili nome/path/write_enabled per
# uso successivo.

log "verifica manifest ${MANIFEST_ID}"
verify_out="$(
    python3 - "${MANIFEST_JSON}" "${MANIFEST_HMAC}" "${BOOTSTRAP_KEY}" \
              "${PAYLOAD_DIR}" "${REPLAY_WINDOW_MIN}" "${PROJECTS_ROOT}" \
              "${MANIFEST_ID}" <<'PYEOF'
import hashlib
import hmac
import json
import os
import re
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path

manifest_path, hmac_path, key_path, payload_dir, replay_window_s, projects_root, manifest_id = sys.argv[1:8]
replay_window = timedelta(minutes=int(replay_window_s))

def die(msg):
    print(f"FAIL: {msg}", file=sys.stderr)
    sys.exit(2)

# Leggi manifest + hmac + key
try:
    manifest_bytes = Path(manifest_path).read_bytes()
    expected_hmac = Path(hmac_path).read_text().strip()
    key = Path(key_path).read_bytes().strip()
except OSError as e:
    die(f"lettura file fallita: {e}")

# HMAC verify (constant-time)
computed = hmac.new(key, manifest_bytes, hashlib.sha256).hexdigest()
if not hmac.compare_digest(computed, expected_hmac):
    die("HMAC del manifest NON valido — chiave sbagliata o manifest manomesso")

# Parse JSON
try:
    m = json.loads(manifest_bytes)
except json.JSONDecodeError as e:
    die(f"manifest non è JSON valido: {e}")

# Schema check (minimale)
required = {"version", "manifest_id", "name", "path_target",
            "sha256_tree", "config_block", "ts"}
missing = required - set(m.keys())
if missing:
    die(f"campi mancanti nel manifest: {sorted(missing)}")
if m["version"] != 1:
    die(f"versione manifest non supportata: {m['version']}")
if m["manifest_id"] != manifest_id:
    die(f"manifest_id mismatch: argv={manifest_id} vs manifest={m['manifest_id']}")

# Name regex: alfanumerico-inizio E alfanumerico-fine (no trailing dash).
# Length 2-40. Stesso vincolo applicato lato make-test-bundle.sh e dal tool
# bridge (quando esisterà).
if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,38}[a-z0-9]", m["name"]):
    die(f"name non valido: {m['name']!r}")

# path_target deve essere ESATTAMENTE <PROJECTS_ROOT>/<name>
expected_path = f"{projects_root.rstrip('/')}/{m['name']}"
if m["path_target"] != expected_path:
    die(f"path_target inatteso: {m['path_target']} vs {expected_path}")

# Timestamp window
try:
    ts = datetime.fromisoformat(m["ts"].replace("Z", "+00:00"))
except ValueError as e:
    die(f"ts non parsabile: {e}")
now = datetime.now(timezone.utc)
age = now - ts
if age < timedelta(0):
    die(f"ts nel futuro: {age}")
if age > replay_window:
    die(f"ts troppo vecchio: {age} > {replay_window} (replay window)")

# config_block sanity
cb = m["config_block"]
if not isinstance(cb, dict):
    die("config_block non è un dict")
if cb.get("path") != expected_path:
    die(f"config_block.path inatteso: {cb.get('path')} vs {expected_path}")
if not isinstance(cb.get("write_enabled"), bool):
    die("config_block.write_enabled deve essere bool")
# command_whitelist: lista di stringhe regex anchored
wl = cb.get("command_whitelist") or []
if not isinstance(wl, list) or not all(isinstance(x, str) for x in wl):
    die("config_block.command_whitelist deve essere lista di stringhe")
# Superwhitelist hardcoded di argv0 consentiti. Approccio invertito vs
# denylist su substring (bypassabile con character class: ad es. `^[r]m( .*)?$`
# regex-matcha `rm <x>` ma non contiene la substring letterale `rm` —
# vedi R1 nella code review che ha motivato questo refactor).
#
# Il pattern del manifest DEVE iniziare con `^<argv0>` dove argv0 è una
# STRINGA LETTERALE in ALLOWED_CMD_NAMES (regex anchored e estraibile).
# Per progetti con CLI custom non standard: registrare via questo path
# con un pattern `^<argv0>( .*)?$` minimale, poi editare a mano
# /etc/devbox-bridge/config.yaml dopo la registrazione (richiede root).
ALLOWED_CMD_NAMES = frozenset({
    "pytest", "ruff", "mypy", "black", "isort", "tox", "flake8",
    "go", "golangci-lint",
    "npm", "npx", "pnpm", "yarn",
    "cargo",
    "alembic", "prisma",
    "pwsh",
})
# Estrae argv0 letterale dopo `^`. Il carattere dopo argv0 può essere
# spazio, paren aperta (sub-pattern), `$` (end-anchor) o end-of-string.
# Se argv0 contiene caratteri regex (`[`, `.`, `*`, ecc.), il match fallisce
# e il pattern viene rifiutato.
ARGV0_RE = re.compile(r"^\^([a-z][a-z0-9-]*)(?:\s|\(|\$|$)")
for w in wl:
    m_argv = ARGV0_RE.match(w)
    if not m_argv:
        die(f"whitelist pattern: argv0 non estraibile (deve iniziare con ^<cmdname> letterale): {w!r}")
    argv0 = m_argv.group(1)
    if argv0 not in ALLOWED_CMD_NAMES:
        die(f"whitelist pattern: comando '{argv0}' non in ALLOWED_CMD_NAMES "
            f"(edita /etc/devbox-bridge/config.yaml a mano se davvero serve): {w!r}")

# sha256_tree: walk del payload, file ordinati per rel-path,
# hash di {rel_path}\0{file_sha256}\n concatenati.
payload = Path(payload_dir)
if not payload.is_dir() or payload.is_symlink():
    die("payload/ non è dir o è symlink")

tree_hasher = hashlib.sha256()
file_count = 0
total_bytes = 0
for root, dirs, files in os.walk(payload, followlinks=False):
    dirs.sort()
    files.sort()
    for fn in files:
        fp = Path(root) / fn
        if fp.is_symlink():
            die(f"symlink interno al payload: {fp.relative_to(payload)}")
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

computed_tree = tree_hasher.hexdigest()
if not hmac.compare_digest(computed_tree, m["sha256_tree"]):
    die(f"sha256_tree mismatch: payload manomesso? "
        f"computed={computed_tree} expected={m['sha256_tree']}")

# Export per bash via stdout (formato shell-parsabile, no spaces)
print(f"NAME={m['name']}")
print(f"PATH_TARGET={m['path_target']}")
print(f"WRITE_ENABLED={'true' if cb['write_enabled'] else 'false'}")
print(f"FILE_COUNT={file_count}")
print(f"TOTAL_BYTES={total_bytes}")
PYEOF
)" || fail "verifica manifest fallita (vedi stderr sopra)"

# Esporta le variabili nel contesto bash
eval "${verify_out}"
readonly MANIFEST_NAME="${NAME}"
readonly MANIFEST_PATH="${PATH_TARGET}"
readonly MANIFEST_WRITE="${WRITE_ENABLED}"

log "manifest valido: name=${MANIFEST_NAME} path=${MANIFEST_PATH} write=${MANIFEST_WRITE} files=${FILE_COUNT} bytes=${TOTAL_BYTES}"

# --- 4. Idempotency check: progetto già registrato? -----------------------
#
# Se path_target esiste già E owner è hypn0 E il blocco progetto è già nel
# config con stesso path: assumiamo che un run precedente sia andato a buon
# fine e siamo qui solo per ri-applicare ACL+drop-in (es. dopo crash a metà).
# In quel caso skippiamo mv e merge, eseguiamo solo install.sh + restart.

SKIP_MV=false
SKIP_MERGE=false

if [[ -e "${MANIFEST_PATH}" ]]; then
    [[ -L "${MANIFEST_PATH}" ]] \
        && fail "${MANIFEST_PATH} esiste ed è un symlink — rifiutato"
    [[ -d "${MANIFEST_PATH}" ]] \
        || fail "${MANIFEST_PATH} esiste ma non è una directory — rifiutato"
    current_owner="$(stat -c '%U' "${MANIFEST_PATH}")"
    [[ "${current_owner}" == "${OWNER_USER}" ]] \
        || fail "${MANIFEST_PATH} esiste con owner '${current_owner}' (atteso '${OWNER_USER}') — rifiutato"
    warn "${MANIFEST_PATH} esiste già con owner ${OWNER_USER} — skip move (idempotency)"
    SKIP_MV=true
fi

if python3 - "${CONFIG_FILE}" "${MANIFEST_NAME}" "${MANIFEST_PATH}" <<'PYEOF'
import sys, yaml
cfg_path, name, expected_path = sys.argv[1:4]
with open(cfg_path) as f:
    cfg = yaml.safe_load(f) or {}
projects = cfg.get("projects") or {}
p = projects.get(name)
if isinstance(p, dict) and p.get("path") == expected_path:
    sys.exit(0)  # già presente
sys.exit(1)
PYEOF
then
    warn "blocco '${MANIFEST_NAME}' già in ${CONFIG_FILE} con stesso path — skip merge (idempotency)"
    SKIP_MERGE=true
fi

# --- 5. Move staging → projects root --------------------------------------

if [[ "${SKIP_MV}" == "false" ]]; then
    log "sposto payload in ${MANIFEST_PATH}"
    # mv atomico se /var/lib e /home sono sullo stesso filesystem.
    # Se non lo sono (rare ma possibile), mv farà copy-then-delete: meno
    # atomico ma comunque corretto. La staging dir resta dopo (la
    # cancelliamo al cleanup finale).
    mv "${PAYLOAD_DIR}" "${MANIFEST_PATH}"
    chown -R "${OWNER_USER}:${OWNER_GROUP}" "${MANIFEST_PATH}"
    # Sanity: dopo mv non deve restare nulla in payload/
    [[ ! -e "${PAYLOAD_DIR}" ]] || fail "mv è stato parziale, payload/ esiste ancora"
fi

# --- 6. Merge atomico del blocco progetto in config.yaml ------------------

if [[ "${SKIP_MERGE}" == "false" ]]; then
    log "merge blocco '${MANIFEST_NAME}' in ${CONFIG_FILE}"

    # Backup automatico prima del merge — ruamel.yaml preserva i commenti
    # ma teniamo una copia per recovery manuale (path predicibile,
    # ownership originale preservata via `cp -p`).
    config_backup="${CONFIG_FILE}.bak.$(date -u +%Y%m%d-%H%M%S)"
    log "backup config in ${config_backup}"
    cp -p "${CONFIG_FILE}" "${config_backup}"

    tmp_cfg="$(mktemp -p "${CONFIG_DIR}" .config.yaml.tmp.XXXXXX)"
    trap 'rm -f "${tmp_cfg}"' EXIT

    python3 - "${CONFIG_FILE}" "${MANIFEST_JSON}" "${tmp_cfg}" <<'PYEOF'
import io, json, sys
try:
    from ruamel.yaml import YAML
except ImportError:
    raise SystemExit("ruamel.yaml non installato — rilancia deploy/install.sh "
                     "(aggiunge python3-ruamel.yaml ad apt-get)")
import yaml as pyyaml  # solo per sanity re-parse (read-only)

yaml_rt = YAML()
yaml_rt.preserve_quotes = True

cfg_path, manifest_path, out_path = sys.argv[1:4]
with open(cfg_path) as f:
    cfg = yaml_rt.load(f) or {}
with open(manifest_path) as f:
    m = json.load(f)
name = m["name"]
block = m["config_block"]
cfg.setdefault("projects", {})
if not isinstance(cfg["projects"], dict):
    # CommentedMap di ruamel è dict-subclass, isinstance dict-check passa.
    raise SystemExit(f"projects: nel config non è un mapping (è {type(cfg['projects']).__name__})")
if name in cfg["projects"]:
    # Idempotency caso edge: existing block diverso da block proposto.
    # Più sicuro rifiutare che sovrascrivere silenziosamente.
    existing = cfg["projects"][name]
    # Confronto value-wise: CommentedMap == dict funziona per uguaglianza di contenuto.
    if dict(existing) != block:
        raise SystemExit(f"progetto '{name}' esiste già nel config con valori diversi — rifiutato")
cfg["projects"][name] = block

# Dump con ruamel (preserva commenti del config originale)
buf = io.StringIO()
yaml_rt.dump(cfg, buf)
dumped = buf.getvalue()

# Sanity re-parse con PyYAML safe_load (read-only check, no commenti da preservare)
reloaded = pyyaml.safe_load(dumped)
if (reloaded.get("projects") or {}).get(name, {}).get("path") != block["path"]:
    raise SystemExit("sanity re-parse fallita")

with open(out_path, "w") as f:
    f.write(dumped)
PYEOF

    # Permessi/ownership prima del rename (atomico su stesso fs)
    chown root:"${SVC_GROUP}" "${tmp_cfg}"
    chmod 0640 "${tmp_cfg}"
    mv "${tmp_cfg}" "${CONFIG_FILE}"
    trap - EXIT
fi

# --- 7. Applica config: install.sh + restart ------------------------------

log "lancio install.sh per applicare ACL + drop-in systemd"
"${INSTALL_SH}"

log "restart ${UNIT_NAME} per ricaricare config"
systemctl restart "${UNIT_NAME}"
# Polling: `systemctl restart` ritorna prima che Type=simple/exec sia ready.
# Attendiamo fino a 10s che is-active diventi true (un primo controllo
# immediato gestisce il caso happy in cui il bridge era già up).
for _ in 1 2 3 4 5 6 7 8 9 10; do
    systemctl is-active --quiet "${UNIT_NAME}" && break
    sleep 1
done
systemctl is-active --quiet "${UNIT_NAME}" \
    || fail "${UNIT_NAME} non è active 10s dopo restart — controlla 'journalctl -u ${UNIT_NAME} -n 50'"

# --- 8. Cleanup staging ---------------------------------------------------

log "cleanup staging bundle ${BUNDLE_DIR}"
# Rinominiamo prima in .consumed così se il delete fallisce, un retry non
# ri-processa lo stesso bundle (replay protection lato filesystem).
consumed="${BUNDLE_DIR}.consumed.$(date +%s)"
mv "${BUNDLE_DIR}" "${consumed}"
rm -rf "${consumed}"

# --- 9. Success ----------------------------------------------------------

audit_emit "success"

cat <<EOF

============================================================
PROGETTO REGISTRATO: ${MANIFEST_NAME}
============================================================
  path:          ${MANIFEST_PATH}
  write_enabled: ${MANIFEST_WRITE}
  files:         ${FILE_COUNT}
  bytes:         ${TOTAL_BYTES}
  manifest_id:   ${MANIFEST_ID}
  audit log:     ${AUDIT_LOG}

Il bridge è stato riavviato — i tool MCP vedono il nuovo
progetto immediatamente (list_projects per verifica).
============================================================
EOF

log "register-project.sh completato"
