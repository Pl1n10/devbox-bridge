# SETUP

> Step-by-step per installare devbox-bridge sulla devbox e registrarlo come
> custom connector su claude.ai. Stato step 7: setup locale funzionante; deploy
> systemd/cloudflared definitivo ancora da completare nello step 11/12.

## 1. Dipendenze

Setup locale dalla root repo:

```bash
python3.12 -m venv .venv
source .venv/bin/activate
pip install -r requirements.lock
pip install -e . --no-deps
```

Per sviluppo/test:

```bash
pip install -e '.[dev]'
```

## 2. Configurazione progetti

```bash
cp config.yaml.example config.yaml
```

Regole pratiche:

- abilita solo progetti opt-in sotto `projects:`;
- lascia `write_enabled: false` finche non serve davvero;
- `allow_push: true` richiede `write_enabled: true`;
- non usare whitelist comando permissive tipo `^.*$`;
- per i progetti finanziari mantieni solo test/lint/backtest dry-run.

Il server legge `./config.yaml` di default. Per usare un path diverso:

```bash
export DEVBOX_BRIDGE_CONFIG=/etc/devbox-bridge/config.yaml
```

## 3. Avvio locale

```bash
python -m devbox_bridge.server
```

Endpoint locale:

```text
http://127.0.0.1:8765/mcp
```

Ogni richiesta MCP deve includere:

```text
Authorization: Bearer <token>
```

## 4. Lanciare `install.sh`

TODO step 11: cosa fa, dove finisce il token, come custodirlo. Non deve fare
`systemctl enable/start` automatici e non deve aprire firewall.

## 5. Cloudflare Tunnel

(TODO: aggiunta ingress a `mcpdev.robertonovara.me`, restart cloudflared)

## 6. Cloudflare Access (opzionale ma consigliato)

(TODO: come mettere Access policy sul tunnel come secondo layer di auth)

## 7. Registrare il connector su claude.ai

URL previsto:

```text
https://mcpdev.robertonovara.me/mcp
```

Header:

```text
Authorization: Bearer <token>
```

## 8. Test connessione

Smoke test previsto: chiamare `list_projects` dal client MCP e verificare che
risponda con i progetti configurati. Con `audit.audit_reads=false`, questa
chiamata non scrive audit log; i write e gli auth fail invece si.
