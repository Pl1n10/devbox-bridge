# SETUP

> Step-by-step per installare devbox-bridge sulla devbox e registrarlo come
> custom connector su claude.ai. **Skeleton — completare nello step 12.**

## 1. Dipendenze

(TODO: comandi apt + python venv + pip install -e .)

## 2. Configurazione progetti

(TODO: come popolare `config.yaml` partendo da `config.yaml.example`,
con regole di sicurezza per `write_enabled` e `command_whitelist`)

## 3. Lanciare `install.sh`

(TODO: cosa fa, dove finisce il token, come custodirlo)

## 4. Cloudflare Tunnel

(TODO: aggiunta ingress a `mcpdev.robertonovara.me`, restart cloudflared)

## 5. Cloudflare Access (opzionale ma consigliato)

(TODO: come mettere Access policy sul tunnel come secondo layer di auth)

## 6. Registrare il connector su claude.ai

(TODO: URL, header `Authorization: Bearer <token>`, smoke test)

## 7. Test connessione

(TODO: chiamata a `list_projects` da claude.ai e verifica audit log)
