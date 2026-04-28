#!/usr/bin/env bash
# TODO (step 11): installer idempotente.
# Bozza dello scope:
#   - useradd -r -s /usr/sbin/nologin devbox-bridge   (se non esiste)
#   - mkdir -p /etc/devbox-bridge /var/log/devbox-bridge
#   - chown devbox-bridge:devbox-bridge /var/log/devbox-bridge
#   - chmod 750 /etc/devbox-bridge
#   - se /etc/devbox-bridge/token.sha256 NON esiste:
#       genera token random (openssl rand -hex 32)
#       scrivi sha256(token) in /etc/devbox-bridge/token.sha256 (chmod 600)
#       stampa UNA VOLTA in stdout il token plain con avviso di salvarlo subito
#   - copia deploy/devbox-bridge.service in /etc/systemd/system/
#   - systemctl daemon-reload
#   - NON enable/start automatici — stampare istruzioni:
#       echo "Per avviare:  sudo systemctl enable --now devbox-bridge"
#
# Lo script DEVE essere ri-eseguibile senza side effect distruttivi
# (no rigenerazione token se esiste, no overwrite di config.yaml).

set -euo pipefail

echo "TODO: install.sh non ancora implementato — vedi step 11 del brief."
exit 1
