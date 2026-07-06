#!/usr/bin/env bash
# setup-notes-access.sh — abilita i tool notes_* del bridge sul vault ~/notes.
#
# Cosa fa (root-only, complementare a install.sh — NON lo sostituisce):
#   1. Verifica che il vault esista e sia un repo git.
#   2. ACL sul vault:
#        - u:devbox-bridge:rwX ricorsivo + default ACL (il bridge scrive
#          in llm/ e inbox/ e committa in .git/);
#        - u:hypn0:rwX come default ACL (i file creati dal service user
#          devono restare gestibili dal cron pull di hypn0).
#      Traversal --x su /home/hypn0 è già garantito da install.sh (7b).
#   3. Deploy key dedicata in /etc/devbox-bridge/notes_ssh_key (genera SE
#      manca, stampa la pubkey UNA volta con le istruzioni per registrarla
#      su Gitea come deploy key WRITE del repo notes). known_hosts pinnato
#      via ssh-keyscan in /etc/devbox-bridge/notes_known_hosts.
#   4. Gitconfig: /etc/devbox-bridge/notes_gitconfig con identity dei
#      commit MCP + core.sshCommand (chiave e known_hosts dedicati),
#      incluso nel gitconfig globale del SOLO service user con
#      `includeIf gitdir:<vault>/`. Motivo: repo-local romperebbe il cron
#      pull di hypn0 (la chiave non gli è leggibile), globale senza
#      includeIf romperebbe i push dei progetti verso GitHub (known_hosts
#      pinnato solo su Gitea). safe.directory per il vault come per i
#      progetti di install.sh.
#   5. Drop-in systemd notes.conf: Environment NOTES_* + ReadWritePaths
#      sul vault. File SEPARATO da projects.conf (che install.sh rigenera
#      da zero a ogni run).
#
# Idempotenza: rieseguibile. Non rigenera la chiave se esiste, riscrive
# known_hosts / notes_gitconfig / drop-in da zero, setfacl -m è additivo.
#
# Uso:
#   sudo GITEA_SSH_HOST=mnemosyne.taild339b.ts.net GITEA_SSH_PORT=2222 \
#        deploy/setup-notes-access.sh

set -euo pipefail
IFS=$'\n\t'

readonly SVC_USER="devbox-bridge"
readonly SVC_GROUP="devbox-bridge"
readonly CONFIG_DIR="/etc/devbox-bridge"
readonly VAULT_OWNER="hypn0"
readonly VAULT="${NOTES_ROOT:-/home/${VAULT_OWNER}/notes}"
readonly KEY_FILE="${CONFIG_DIR}/notes_ssh_key"
readonly KNOWN_HOSTS_FILE="${CONFIG_DIR}/notes_known_hosts"
readonly GITCONFIG_FILE="${CONFIG_DIR}/notes_gitconfig"
readonly UNIT_NAME="devbox-bridge.service"
readonly DROPIN_DIR="/etc/systemd/system/${UNIT_NAME}.d"
readonly DROPIN_FILE="${DROPIN_DIR}/notes.conf"
readonly GITEA_SSH_HOST="${GITEA_SSH_HOST:-mnemosyne.taild339b.ts.net}"
readonly GITEA_SSH_PORT="${GITEA_SSH_PORT:-2222}"
readonly NOTES_WRITE_DIRS="${NOTES_WRITE_DIRS:-llm,inbox}"

log()  { printf '\033[1;34m[notes-access]\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31m[notes-access]\033[0m %s\n' "$*" >&2; exit 1; }

# --- 1. Pre-flight ---------------------------------------------------------

[[ ${EUID} -eq 0 ]]        || fail "deve girare come root (sudo $0)"
[[ -d "${VAULT}/.git" ]]   || fail "vault '${VAULT}' non esiste o non è un repo git"
[[ -d "${CONFIG_DIR}" ]]   || fail "${CONFIG_DIR} non esiste: eseguire prima deploy/install.sh"
getent passwd "${SVC_USER}" > /dev/null || fail "utente ${SVC_USER} non esiste: eseguire prima deploy/install.sh"

# --- 2. ACL sul vault --------------------------------------------------------

log "applico ACL rwX + default per ${SVC_USER} e ${VAULT_OWNER} su ${VAULT}"
setfacl -R    -m "u:${SVC_USER}:rwX"    "${VAULT}"
setfacl -R -d -m "u:${SVC_USER}:rwX"    "${VAULT}"
setfacl -R -d -m "u:${VAULT_OWNER}:rwX" "${VAULT}"

# --- 3. Deploy key + known_hosts ----------------------------------------------

if [[ ! -f "${KEY_FILE}" ]]; then
    log "genero deploy key ed25519 in ${KEY_FILE}"
    ssh-keygen -t ed25519 -N '' -C "devbox-bridge-notes@devbox" -f "${KEY_FILE}" -q
    chown root:"${SVC_GROUP}" "${KEY_FILE}" "${KEY_FILE}.pub"
    chmod 0640 "${KEY_FILE}"
    chmod 0644 "${KEY_FILE}.pub"
    cat <<KEYEOF

============================================================
DEPLOY KEY — registrala su Gitea sul repo notes con accesso
in SCRITTURA (Settings → Deploy Keys → Add, spunta write):
============================================================
$(cat "${KEY_FILE}.pub")
============================================================

KEYEOF
else
    log "deploy key esistente, non rigenero: ${KEY_FILE}"
fi

log "rigenero ${KNOWN_HOSTS_FILE} via ssh-keyscan ${GITEA_SSH_HOST}:${GITEA_SSH_PORT}"
scan="$(ssh-keyscan -p "${GITEA_SSH_PORT}" "${GITEA_SSH_HOST}" 2>/dev/null)"
[[ -n "${scan}" ]] || fail "ssh-keyscan non ha risposto da ${GITEA_SSH_HOST}:${GITEA_SSH_PORT}"
printf '%s\n' "${scan}" > "${KNOWN_HOSTS_FILE}"
chown root:"${SVC_GROUP}" "${KNOWN_HOSTS_FILE}"
chmod 0644 "${KNOWN_HOSTS_FILE}"

# --- 4. Gitconfig del service user ---------------------------------------------

log "rigenero ${GITCONFIG_FILE} (identity commit MCP + sshCommand)"
cat > "${GITCONFIG_FILE}" <<GITEOF
# GENERATO da deploy/setup-notes-access.sh — NON modificare a mano.
# Incluso via includeIf gitdir:${VAULT}/ SOLO nel gitconfig di ${SVC_USER}.
[user]
	name = devbox-bridge (MCP)
	email = devbox-bridge@devbox.local
[core]
	sshCommand = ssh -i ${KEY_FILE} -o IdentitiesOnly=yes -o UserKnownHostsFile=${KNOWN_HOSTS_FILE} -o StrictHostKeyChecking=yes
GITEOF
chown root:"${SVC_GROUP}" "${GITCONFIG_FILE}"
chmod 0644 "${GITCONFIG_FILE}"

if ! sudo -u "${SVC_USER}" git config --global --get-all safe.directory \
        2>/dev/null | grep -qxF "${VAULT}"; then
    log "aggiungo safe.directory ${VAULT} al gitconfig di ${SVC_USER}"
    sudo -u "${SVC_USER}" git config --global --add safe.directory "${VAULT}"
fi

log "collego ${GITCONFIG_FILE} con includeIf gitdir:${VAULT}/ per ${SVC_USER}"
sudo -u "${SVC_USER}" git config --global \
    "includeIf.gitdir:${VAULT}/.path" "${GITCONFIG_FILE}"

# --- 5. Drop-in systemd --------------------------------------------------------

log "rigenero drop-in systemd: ${DROPIN_FILE}"
install -d -m 0755 -o root -g root "${DROPIN_DIR}"
{
    echo "# GENERATO da deploy/setup-notes-access.sh — NON modificare a mano."
    echo "# Rigenerato: $(date --iso-8601=seconds)"
    echo "[Service]"
    echo "Environment=NOTES_ROOT=${VAULT}"
    echo "Environment=NOTES_WRITE_DIRS=${NOTES_WRITE_DIRS}"
    echo "ReadWritePaths=${VAULT}"
} > "${DROPIN_FILE}"
chmod 0644 "${DROPIN_FILE}"
systemctl daemon-reload

# --- 6. Post-condizioni --------------------------------------------------------

getfacl --omit-header "${VAULT}" | grep -q "^user:${SVC_USER}:rwx" \
    || fail "post-check: ACL di ${SVC_USER} non presente su ${VAULT}"
sudo -u "${SVC_USER}" git -C "${VAULT}" status --porcelain > /dev/null \
    || fail "post-check: git status nel vault fallisce come ${SVC_USER}"
grep -q "NOTES_ROOT=${VAULT}" "${DROPIN_FILE}" \
    || fail "post-check: drop-in senza NOTES_ROOT"

cat <<NEXTEOF

============================================================
NEXT STEPS:
1) Registra la deploy key su Gitea (se stampata sopra) con WRITE.
2) Verifica il push come service user:
     sudo -u ${SVC_USER} git -C ${VAULT} ls-remote origin HEAD
3) Riavvia il servizio per caricare env e ReadWritePaths:
     sudo systemctl restart ${UNIT_NAME}
============================================================
NEXTEOF

log "setup-notes-access.sh completato"
