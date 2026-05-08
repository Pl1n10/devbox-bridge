#!/usr/bin/env bash
# install.sh — installer host idempotente per devbox-bridge.
#
# Cosa fa (root-only, single-tenant Ubuntu 24.04 con utente hypn0):
#   1. Crea l'utente di servizio `devbox-bridge` (no-login) e lo aggiunge a
#      `systemd-journal` per leggere il proprio log.
#   2. Prepara /etc/devbox-bridge (config + token), /var/log/devbox-bridge
#      (audit + app log), /opt/devbox-bridge (codice + venv).
#   3. Genera bearer token random; ne salva l'sha256 e stampa il plain UNA
#      VOLTA in stdout.
#   4. Verifica supporto ACL sul filesystem di /home/hypn0/projects via
#      probe (setfacl + getfacl su file mktemp), non grep su mount options.
#   5. Parsea /etc/devbox-bridge/config.yaml (canonicalizza path, rifiuta
#      symlink, rifiuta path fuori da /home/hypn0/projects) e applica ACL
#      chirurgiche per progetto:
#        - r-X ricorsivo per progetti read-only;
#        - rwX ricorsivo + default ACL per progetti write_enabled.
#   6. Genera /etc/systemd/system/devbox-bridge.service.d/projects.conf con
#      `ReadWritePaths=` per ogni progetto write_enabled (defense in depth:
#      ACL applicativa + namespace systemd kernel-level). Il drop-in viene
#      sempre riscritto da zero — anche vuoto se nessun progetto è rw —
#      così che downgrade rw→ro non lasci entry stale.
#   7. Installa la unit base e fa daemon-reload (NO enable/start).
#
# Cosa NON fa (deve farlo l'operatore, le istruzioni vengono stampate):
#   - clone del codice in /opt/devbox-bridge,
#   - creazione venv e pip install,
#   - systemctl enable --now,
#   - merge ingress cloudflared,
#   - apertura porte sul firewall.
#
# Idempotenza: rieseguibile. Non rigenera token se esiste, non sovrascrive
# /etc/devbox-bridge/config.yaml se esiste, ricrea drop-in da zero, riapplica
# ACL (setfacl -m è idempotente). Se cambi `write_enabled: true → false` per
# un progetto, rimuovi le ACL stale a mano:
#     sudo setfacl -R -x u:devbox-bridge <path>
#     sudo setfacl -R -d -x u:devbox-bridge <path>
# poi rilancia install.sh per riapplicare la configurazione corrente.

set -euo pipefail
IFS=$'\n\t'

readonly SVC_USER="devbox-bridge"
readonly SVC_GROUP="devbox-bridge"
readonly SVC_HOME="/opt/devbox-bridge"
readonly CONFIG_DIR="/etc/devbox-bridge"
readonly CONFIG_FILE="${CONFIG_DIR}/config.yaml"
readonly TOKEN_HASH_FILE="${CONFIG_DIR}/token.sha256"
readonly LOG_DIR="/var/log/devbox-bridge"
readonly UNIT_NAME="devbox-bridge.service"
readonly UNIT_DEST="/etc/systemd/system/${UNIT_NAME}"
readonly DROPIN_DIR="/etc/systemd/system/${UNIT_NAME}.d"
readonly DROPIN_FILE="${DROPIN_DIR}/projects.conf"
readonly PROJECTS_ROOT="/home/hypn0/projects"

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
readonly SCRIPT_DIR
REPO_ROOT="$(dirname -- "${SCRIPT_DIR}")"
readonly REPO_ROOT
readonly UNIT_SRC="${SCRIPT_DIR}/${UNIT_NAME}"
readonly CONFIG_EXAMPLE="${REPO_ROOT}/config.yaml.example"

log()  { printf '\033[1;34m[install]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[install]\033[0m %s\n' "$*" >&2; }
fail() { printf '\033[1;31m[install]\033[0m %s\n' "$*" >&2; exit 1; }

# --- 1. Pre-flight --------------------------------------------------------

[[ ${EUID} -eq 0 ]]            || fail "deve girare come root (sudo $0)"
[[ -f "${UNIT_SRC}" ]]         || fail "unit template non trovato: ${UNIT_SRC}"
[[ -f "${CONFIG_EXAMPLE}" ]]   || fail "config.yaml.example non trovato: ${CONFIG_EXAMPLE}"
[[ -d "${PROJECTS_ROOT}" ]]    || fail "directory progetti non esiste: ${PROJECTS_ROOT}"

# --- 2. Apt deps ----------------------------------------------------------

log "verifico/installo pacchetti host (acl, python3-yaml, ripgrep)"
DEBIAN_FRONTEND=noninteractive apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -qq -y --no-install-recommends \
    acl python3-yaml ripgrep > /dev/null

# --- 3. Service user ------------------------------------------------------

if ! getent passwd "${SVC_USER}" > /dev/null; then
    log "creo utente di servizio ${SVC_USER}"
    useradd --system --shell /usr/sbin/nologin --no-create-home \
            --home-dir "${SVC_HOME}" "${SVC_USER}"
else
    log "utente ${SVC_USER} già esistente"
fi

# --- 4. Gruppo systemd-journal (per read_journalctl con whitelist default) -

if ! id -nG "${SVC_USER}" | tr ' ' '\n' | grep -qx 'systemd-journal'; then
    log "aggiungo ${SVC_USER} al gruppo systemd-journal"
    usermod -aG systemd-journal "${SVC_USER}"
fi
id -nG "${SVC_USER}" | tr ' ' '\n' | grep -qx 'systemd-journal' \
    || fail "${SVC_USER} non è nel gruppo systemd-journal — read_journalctl non funzionerebbe"

# --- 5. Directory di sistema ---------------------------------------------

log "preparo directory di sistema"
# /etc/devbox-bridge: owner root, group SVC, 0750 → bridge legge ma non scrive
install -d -m 0750 -o root          -g "${SVC_GROUP}" "${CONFIG_DIR}"
# /var/log/devbox-bridge: owner SVC, 0750 → bridge scrive log + audit
install -d -m 0750 -o "${SVC_USER}" -g "${SVC_GROUP}" "${LOG_DIR}"
# /opt/devbox-bridge: owner SVC, 0750 → bridge ci farà clone + venv
install -d -m 0750 -o "${SVC_USER}" -g "${SVC_GROUP}" "${SVC_HOME}"

# --- 6. Copia config.yaml.example SE MANCA (no overwrite) -----------------

if [[ ! -f "${CONFIG_FILE}" ]]; then
    log "primo install: copio ${CONFIG_EXAMPLE} → ${CONFIG_FILE}"
    install -m 0640 -o root -g "${SVC_GROUP}" "${CONFIG_EXAMPLE}" "${CONFIG_FILE}"
    warn "edita ${CONFIG_FILE} per attivare i progetti voluti, poi rilancia $0"
else
    log "config esistente, non sovrascrivo: ${CONFIG_FILE}"
fi

# --- 7. Filesystem ACL probe --------------------------------------------------

log "verifico supporto ACL sul filesystem di ${PROJECTS_ROOT}"
acl_probe="$(mktemp -p "${PROJECTS_ROOT}" .acl-probe.XXXXXX)" \
    || fail "impossibile creare file di probe in ${PROJECTS_ROOT}"
trap 'rm -f "${acl_probe}"' EXIT
setfacl -m "u:nobody:r" "${acl_probe}" 2>/dev/null \
    || fail "setfacl ha fallito su ${PROJECTS_ROOT} — ACL non abilitate sul filesystem"
getfacl --omit-header "${acl_probe}" 2>/dev/null | grep -q '^user:nobody:r' \
    || fail "setfacl ha scritto ma getfacl non rilegge — fs in stato inconsistente"
rm -f "${acl_probe}"
trap - EXIT

# --- 7b. ACL traversal sui parent path ------------------------------------
#
# Le ACL chirurgiche sui project path NON aiutano se i parent non sono
# eseguibili dal service user. Tipico: /home/hypn0 è 0750 owned by hypn0
# → devbox-bridge non può attraversare per arrivare ai progetti, e tutti
# i tool filesystem tornano EACCES.
#
# Fix least-privilege: setfacl -m u:devbox-bridge:--x sui parent path
# fino a PROJECTS_ROOT (incluso). `--x` permette traversal ma NON
# listing/read della dir → il service user NON può vedere altri file
# in /home/hypn0/, può solo passare. Più chirurgico di chmod o+x (che
# darebbe accesso anche al world).
#
# Idempotente: setfacl -m è additivo, rieseguibile senza side effect.

projects_parent="$(dirname "${PROJECTS_ROOT}")"
for parent in "${projects_parent}" "${PROJECTS_ROOT}"; do
    log "applico ACL traversal-only (--x) per ${SVC_USER} su ${parent}"
    setfacl -m "u:${SVC_USER}:--x" "${parent}" \
        || fail "setfacl --x su ${parent} fallito"
done

# --- 8. Applica ACL per progetto + raccogli path write_enabled ------------

log "applico ACL ai progetti definiti in ${CONFIG_FILE}"
declare -a write_paths=()

while IFS=$'\t' read -r proj_name proj_path proj_write; do
    [[ -z "${proj_name}" ]] && continue

    [[ -L "${proj_path}" ]] \
        && fail "progetto '${proj_name}': '${proj_path}' è un symlink (rifiutato per threat model)"

    canon="$(realpath -e "${proj_path}" 2>/dev/null)" \
        || fail "progetto '${proj_name}': path '${proj_path}' non esiste / non risolvibile"

    [[ "${canon}" == "${PROJECTS_ROOT}/"* || "${canon}" == "${PROJECTS_ROOT}" ]] \
        || fail "progetto '${proj_name}': '${canon}' non è sotto ${PROJECTS_ROOT}"

    if [[ "${proj_write}" == "rw" ]]; then
        log "  ${proj_name} (rw): setfacl -R rwX + default ACL su ${canon}"
        setfacl -R    -m "u:${SVC_USER}:rwX" "${canon}"
        setfacl -R -d -m "u:${SVC_USER}:rwX" "${canon}"
        write_paths+=("${canon}")
    else
        log "  ${proj_name} (ro): setfacl -R r-X su ${canon}"
        setfacl -R    -m "u:${SVC_USER}:r-X" "${canon}"
    fi
done < <(
    python3 - "${CONFIG_FILE}" <<'PYEOF'
import sys, yaml
with open(sys.argv[1]) as f:
    cfg = yaml.safe_load(f) or {}
for name, p in (cfg.get("projects") or {}).items():
    if not isinstance(p, dict) or "path" not in p:
        continue
    write = "rw" if p.get("write_enabled") else "ro"
    print(f"{name}\t{p['path']}\t{write}")
PYEOF
)

# --- 9. Drop-in systemd con ReadWritePaths -------------------------------

log "rigenero drop-in systemd: ${DROPIN_FILE}"
install -d -m 0755 -o root -g root "${DROPIN_DIR}"
{
    echo "# GENERATO da deploy/install.sh — NON modificare a mano."
    echo "# Sorgente di verità: ${CONFIG_FILE}"
    echo "# Rigenerato: $(date --iso-8601=seconds)"
    echo "[Service]"
    if [[ ${#write_paths[@]} -gt 0 ]]; then
        for wp in "${write_paths[@]}"; do
            echo "ReadWritePaths=${wp}"
        done
    fi
} > "${DROPIN_FILE}"
chmod 0644 "${DROPIN_FILE}"

# --- 10. Bearer token: genera SE manca, stampa plain UNA VOLTA ------------

if [[ ! -f "${TOKEN_HASH_FILE}" ]]; then
    log "genero bearer token e ne salvo l'sha256 in ${TOKEN_HASH_FILE}"
    token_plain="$(openssl rand -hex 32)"
    token_hash="$(printf '%s' "${token_plain}" | sha256sum | awk '{print $1}')"
    umask 077
    printf '%s\n' "${token_hash}" > "${TOKEN_HASH_FILE}"
    chown root:"${SVC_GROUP}" "${TOKEN_HASH_FILE}"
    chmod 0640 "${TOKEN_HASH_FILE}"
    cat <<TOKEOF

============================================================
BEARER TOKEN — mostrato UNA SOLA VOLTA, copialo SUBITO
============================================================
${token_plain}
============================================================
Va inserito su claude.ai come header:
    Authorization: Bearer ${token_plain}

Sul disco resta solo l'sha256 in ${TOKEN_HASH_FILE}; il plain
non è recuperabile. Se lo perdi: rm ${TOKEN_HASH_FILE} && rilancia $0.
============================================================

TOKEOF
else
    log "token esistente, non rigenero: ${TOKEN_HASH_FILE}"
fi

# --- 11. Installa unit + daemon-reload -----------------------------------

log "installo unit systemd: ${UNIT_DEST}"
install -m 0644 -o root -g root "${UNIT_SRC}" "${UNIT_DEST}"
systemctl daemon-reload

# --- 12. Istruzioni operatore (NON eseguite in automatico) ---------------

cat <<NEXTEOF

============================================================
NEXT STEPS — da eseguire a mano (l'installer non li fa apposta):
============================================================

1) Deploy del codice come ${SVC_USER} (la dir è già ${SVC_USER}:${SVC_GROUP} 0750):
     sudo -u ${SVC_USER} git clone https://github.com/Pl1n10/devbox-bridge.git ${SVC_HOME}
     sudo -u ${SVC_USER} python3.12 -m venv ${SVC_HOME}/.venv
     sudo -u ${SVC_USER} ${SVC_HOME}/.venv/bin/pip install -r ${SVC_HOME}/requirements.lock
     sudo -u ${SVC_USER} ${SVC_HOME}/.venv/bin/pip install -e ${SVC_HOME} --no-deps

   Nota: install via lockfile + pip install -e . --no-deps è il pattern
   coerente con Dockerfile e CLAUDE.md ("Dependency management"). NON usare
   pip install -e '.[dev]' in produzione (deps di test/lint inutili).

2) Smoke test:
     sudo -u ${SVC_USER} DEVBOX_BRIDGE_CONFIG=${CONFIG_FILE} \\
         ${SVC_HOME}/.venv/bin/devbox-bridge
   (Ctrl-C dopo aver verificato che parta. Per il run definitivo si usa systemd.)

3) Avvio servizio (opt-in esplicito):
     sudo systemctl enable --now ${UNIT_NAME}
     sudo systemctl status ${UNIT_NAME}
     sudo journalctl -u ${UNIT_NAME} -f

4) Cloudflare Tunnel ingress:
   merge dello snippet ${SCRIPT_DIR}/cloudflared-config.yml dentro
   /etc/cloudflared/config.yml, poi:
     sudo systemctl restart cloudflared
     sudo cloudflared tunnel route dns <TUNNEL_NAME> mcpdev.robertonovara.me
   (la riga "tunnel route dns" solo la prima volta.)

5) Registrazione connector su claude.ai:
     URL:    https://mcpdev.robertonovara.me
     Header: Authorization: Bearer <token plain mostrato sopra>

============================================================
NEXTEOF

log "install.sh completato"
