# SETUP — installazione devbox-bridge

Setup end-to-end di `devbox-bridge` su una devbox Ubuntu 24.04
single-tenant (utente operatore: `hypn0`). Valido per lo stato MVP
(step 1-12).

Per il threat model vedi [`SECURITY.md`](SECURITY.md); per il
reference dei tool MCP vedi [`TOOLS.md`](TOOLS.md).

## Pre-requisiti

- Ubuntu 24.04 (o derivata) con `systemd` e filesystem ext4 con ACL
  abilitate (default su `mkfs.ext4` recente).
- `python3.12` + `pip` (`apt install python3.12 python3.12-venv`).
- `git` ≥ 2.40, `ripgrep` (per `search_files`), `tail`, `journalctl`,
  `setfacl`/`getfacl` (`apt install acl`).
- `cloudflared` già configurato sulla devbox per un tunnel esistente
  (questo setup aggiunge solo un ingress, non crea il tunnel).
- Accesso `sudo` all'host. Tutto l'installer gira come `root`; il
  servizio gira come utente dedicato `devbox-bridge` (no-login).

## Layout file/directory

| Path | Owner / mode | Descrizione |
|---|---|---|
| `/opt/devbox-bridge` | `devbox-bridge:devbox-bridge 0750` | Codice + venv. Clonato dall'operatore dopo `install.sh`. |
| `/etc/devbox-bridge` | `root:devbox-bridge 0750` | Config + token. |
| `/etc/devbox-bridge/config.yaml` | `root:devbox-bridge 0640` | Config server. **Mai sovrascritta** dall'installer una volta presente. |
| `/etc/devbox-bridge/token.sha256` | `root:devbox-bridge 0640` | sha256 del bearer token. **Mai rigenerato** se esiste. |
| `/var/log/devbox-bridge` | `devbox-bridge:devbox-bridge 0750` | Audit log + log applicativo. Unica path scrivibile in `ReadWritePaths` di default. |
| `/etc/systemd/system/devbox-bridge.service` | `root:root 0644` | Unit base statica (hardening). |
| `/etc/systemd/system/devbox-bridge.service.d/projects.conf` | `root:root 0644` | Drop-in con `ReadWritePaths=` derivato da `config.yaml` (rigenerato a ogni `install.sh`, anche vuoto). |

## 1. Clone del codice

```bash
sudo mkdir -p /opt/devbox-bridge
# (opzionale fino al primo install.sh che setta owner devbox-bridge:devbox-bridge)
sudo chown "$USER:$USER" /opt/devbox-bridge   # solo per il clone iniziale
git clone https://github.com/Pl1n10/devbox-bridge.git /opt/devbox-bridge
cd /opt/devbox-bridge
```

Setup venv + dipendenze pinned (riproducibile da `requirements.lock`):

```bash
python3.12 -m venv .venv
source .venv/bin/activate
pip install -r requirements.lock
pip install -e . --no-deps
```

Per sviluppo/test (test runner, lint, type checker):

```bash
pip install -e '.[dev]'
```

## 2. Configurazione `config.yaml`

Prima di lanciare l'installer, prepara la config in
`/etc/devbox-bridge/config.yaml`. L'installer copia
`config.yaml.example` solo se la config non esiste già — quindi puoi
metterla a mano o lasciare che venga inizializzata e poi modificarla.

```bash
sudo install -d -m 0750 -o root -g root /etc/devbox-bridge
sudo cp config.yaml.example /etc/devbox-bridge/config.yaml
sudo chown root:root /etc/devbox-bridge/config.yaml
sudo chmod 0640 /etc/devbox-bridge/config.yaml
sudo $EDITOR /etc/devbox-bridge/config.yaml
```

Regole pratiche:

- **Progetti opt-in.** Aggiungi sotto `projects:` solo i progetti che
  vuoi esporre. Ogni voce ha un `name`, un `path` assoluto sotto
  `/home/hypn0/projects/`, e flag `write_enabled`/`allow_push`.
- **`write_enabled: false` di default.** Abilita la scrittura solo
  quando serve davvero — gli ACL chirurgiche e il `ReadWritePaths` di
  systemd vengono applicati di conseguenza.
- **`allow_push: true` richiede `write_enabled: true`** (validato in
  `config.py`).
- **Niente whitelist comando permissive** tipo `^.*$`: la deny list
  resta come backstop ma non puoi affidarti solo a quella. Vedi
  `SECURITY.md → Strategia deny list`.
- **Progetti finanziari** (`evotrader`, `robo-pac-etf`): tieni solo
  test/lint/backtest dry-run nella whitelist. Vedi
  `PM-MCP-PROJECT.md → Cosa il bridge NON farà mai`.

Il server legge `DEVBOX_BRIDGE_CONFIG` se esportata, altrimenti
`./config.yaml`. La unit systemd setta `DEVBOX_BRIDGE_CONFIG=/etc/devbox-bridge/config.yaml`.

## 3. Lanciare `install.sh`

```bash
sudo /opt/devbox-bridge/deploy/install.sh
```

L'installer è **idempotente** e rieseguibile. In sintesi:

1. Crea l'utente `devbox-bridge` (no-login) e lo aggiunge a
   `systemd-journal` (NON `adm` — least privilege, vedi
   `SECURITY.md → Permessi di lettura del journal`).
2. Prepara `/etc/devbox-bridge`, `/var/log/devbox-bridge`,
   `/opt/devbox-bridge` con owner/permissions corretti.
3. Copia `config.yaml.example` → `/etc/devbox-bridge/config.yaml`
   **solo se manca** (rilancio non sovrascrive).
4. Verifica supporto ACL via probe attivo (`setfacl`+`getfacl` su
   `mktemp`). NON fa grep su mount options — su ext4 Ubuntu 24.04 `acl`
   è on-by-default e non compare in `mount`.
5. Parsea `config.yaml` (canonicalizza path con `realpath -e`, rifiuta
   symlink, rifiuta path fuori da `/home/hypn0/projects/`) e applica
   ACL chirurgiche per progetto:
   - `setfacl -R -m u:devbox-bridge:r-X` per progetti read-only;
   - `setfacl -R -m u:devbox-bridge:rwX` + default ACL per progetti
     `write_enabled: true`.
6. Rigenera **da zero** il drop-in
   `/etc/systemd/system/devbox-bridge.service.d/projects.conf` con
   `ReadWritePaths=` per ogni progetto `write_enabled: true`. Anche
   vuoto se zero progetti rw, per evitare entry stale su downgrade
   rw→ro.
7. Genera bearer token random + sha256 in `token.sha256` (0640
   `root:devbox-bridge`) **solo se manca** e stampa il plain UNA
   VOLTA in stdout. Se il token esiste già, NON lo rigenera (per
   rotazione vedi `Recupero token` più sotto).
8. Installa la unit base, fa `daemon-reload`. **NO `enable`/`start`
   automatici** — sono compito dell'operatore alla verifica finale.

Output atteso (esempio):

```
[install] OK: utente devbox-bridge presente, gruppo systemd-journal applicato
[install] OK: ACL probe su /home/hypn0/projects (filesystem supporta ACL)
[install] OK: ACL applicate su projects.devbox-bridge (read-only)
[install] OK: drop-in projects.conf rigenerato (0 path scrivibili)
[install] TOKEN PLAIN (custodiscilo, non verrà mostrato di nuovo):
    Z3hZX0V4YW1wbGVUb2tlbk5vbkVz...
[install] daemon-reload eseguito. NON ho avviato il servizio.
[install] Prossimi passi:
    sudo -u devbox-bridge git clone https://github.com/Pl1n10/devbox-bridge.git /opt/devbox-bridge
    cd /opt/devbox-bridge && sudo -u devbox-bridge python3.12 -m venv .venv
    sudo -u devbox-bridge ./.venv/bin/pip install -r requirements.lock
    sudo -u devbox-bridge ./.venv/bin/pip install -e . --no-deps
    sudo systemctl enable --now devbox-bridge.service
```

## 4. Smoke test locale (pre-systemctl)

Prima di abilitare il servizio, verifica che il bridge parta a mano:

```bash
sudo -u devbox-bridge \
    DEVBOX_BRIDGE_CONFIG=/etc/devbox-bridge/config.yaml \
    /opt/devbox-bridge/.venv/bin/devbox-bridge
```

Endpoint:

```text
http://127.0.0.1:8765/mcp
```

In un altro terminale:

```bash
TOKEN="<plain token stampato dall'installer>"
curl -sS -X POST http://127.0.0.1:8765/mcp \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_projects","arguments":{}}}'
```

Risposta attesa: `200 OK` con la lista progetti `config.yaml`.
Token mancante o sbagliato → `401 unauthorized` (body generico).

Ferma il processo (Ctrl+C) e procedi con systemctl.

## 5. Avvio del servizio

```bash
sudo systemctl enable --now devbox-bridge.service
sudo systemctl status devbox-bridge.service
sudo journalctl -u devbox-bridge.service -n 50 --no-pager
```

Atteso: `active (running)`, log con `Uvicorn running on
http://127.0.0.1:8765`. Riprovare il `curl` di sopra per conferma
end-to-end.

## 6. Cloudflare Tunnel — ingress

`deploy/cloudflared-config.yml` è uno **snippet**, NON un file standalone.
Va **mergiato** nel `config.yml` di `cloudflared` esistente sulla
devbox (di solito `/etc/cloudflared/config.yml`):

```yaml
ingress:
  - hostname: mcpdev.robertonovara.me
    service: http://127.0.0.1:8765
  # ... eventuali altri hostname già presenti ...
  - service: http_status:404   # catch-all, sempre come ULTIMA voce
```

Restart cloudflared e — solo la prima volta — registra il CNAME:

```bash
sudo systemctl restart cloudflared
sudo cloudflared tunnel route dns <TUNNEL_NAME> mcpdev.robertonovara.me
```

Verifica esterna:

```bash
curl -sS -X POST https://mcpdev.robertonovara.me/mcp \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_projects","arguments":{}}}'
```

## 7. Cloudflare Access (raccomandato)

Cloudflare Access davanti al tunnel aggiunge un **secondo layer di
auth** (OAuth Google + email allowlist) prima che la richiesta arrivi
al bridge. Vedi `SECURITY.md → Difese in serie, layer (1)`.

Setup veloce dalla dashboard Cloudflare → Zero Trust → Access →
Applications:

1. Add application → Self-hosted.
2. Application domain: `mcpdev.robertonovara.me`.
3. Identity provider: Google (o quello che preferisci).
4. Policy: `Allow` con `emails` = `claudionetbackup@gmail.com` (e
   eventuali altri).
5. Per il client MCP (claude.ai) abilitare il tipo `Service Token` o
   l'header bypass come da policy Cloudflare.

Lasciare il bridge accessibile solo via tunnel (no porta 8765 esposta
sul firewall pubblico) è già sufficiente per single-tenant; Access è
defense-in-depth.

## 8. Registrare il connector su claude.ai

Su `claude.ai` → Settings → Connectors → Add custom connector:

- **URL:** `https://mcpdev.robertonovara.me/mcp`
- **Auth header:** `Authorization: Bearer <plain token>`

Smoke test dal connector: chiama `list_projects`. Risposta deve
contenere i progetti configurati.

## Verifica finale end-to-end

Da claude.ai (o un altro client MCP), in ordine:

1. `list_projects` → progetti opt-in elencati.
2. `read_file(<progetto>, "README.md")` → contenuto del README.
3. `git_status(<progetto>)` → stato del repo.
4. Se uno dei progetti ha `write_enabled: true` e `test_command`
   configurato: `run_tests(<progetto>)` → suite verde.
5. Su devbox: `tail -f /var/log/devbox-bridge/audit/audit.log` →
   ogni invocazione write/exec genera una riga JSON.

## Recupero token (rotazione)

L'installer **non rigenera** il token se `token.sha256` esiste
(idempotenza fail-secure: un rilancio accidentale non invalida il
token attivo). Per ruotarlo:

```bash
sudo rm /etc/devbox-bridge/token.sha256
sudo /opt/devbox-bridge/deploy/install.sh
```

L'installer rigenera token + sha256 e stampa il nuovo plain UNA
volta. Aggiorna l'header `Authorization` sul connector claude.ai.
Vecchi token: invalidati immediatamente (il bridge confronta solo
sha256 → un nuovo file = un nuovo segreto).

## Aggiornamenti / upgrade

Pull del codice + reinstall pulito da lock:

```bash
cd /opt/devbox-bridge
sudo -u devbox-bridge git fetch --tags
sudo -u devbox-bridge git checkout <new-tag>
sudo -u devbox-bridge ./.venv/bin/pip install -r requirements.lock
sudo -u devbox-bridge ./.venv/bin/pip install -e . --no-deps
sudo /opt/devbox-bridge/deploy/install.sh   # riapplica ACL + drop-in
sudo systemctl restart devbox-bridge.service
```

Se hai modificato `config.yaml` (aggiunto/rimosso progetti, cambiato
`write_enabled`), `install.sh` riapplica le ACL e rigenera il drop-in
di conseguenza. Per rimuovere ACL stale dopo `write_enabled: true →
false`:

```bash
sudo setfacl -R -x u:devbox-bridge <project_path>
sudo setfacl -R -d -x u:devbox-bridge <project_path>
sudo /opt/devbox-bridge/deploy/install.sh   # riapplica ACL ro pulite
```

## Disinstallazione

```bash
sudo systemctl disable --now devbox-bridge.service
sudo rm -rf /etc/systemd/system/devbox-bridge.service \
            /etc/systemd/system/devbox-bridge.service.d
sudo systemctl daemon-reload

# Rimuovi ACL applicate ai progetti (per ogni progetto in config.yaml):
sudo setfacl -R -x u:devbox-bridge <project_path>
sudo setfacl -R -d -x u:devbox-bridge <project_path>

# Cancella stato persistente (token, log, codice):
sudo rm -rf /etc/devbox-bridge /var/log/devbox-bridge /opt/devbox-bridge

# Rimuovi utente di servizio:
sudo userdel devbox-bridge
sudo groupdel devbox-bridge 2>/dev/null || true

# Rimuovi l'ingress da /etc/cloudflared/config.yml e restart cloudflared.
```
