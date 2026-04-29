# PM-MCP-PROJECT.md

> Documento di contesto gestionale del progetto **devbox-bridge** (MCP server custom per la devbox di Roberto). Da affiancare a `HANDOFF.md` (stato tecnico) e `CLAUDE.md` (regole di lavoro). Aggiornare a milestone, non a ogni commit.

---

## Pitch in una frase

Un MCP server self-hosted che permette a claude.ai (e altri client MCP) di operare in modo **controllato e auditabile** sulla devbox di Roberto, esposto via Cloudflare Tunnel su `mcpdev.robertonovara.me`.

---

## Perché esiste

Senza il bridge, ogni interazione tra claude.ai e i 14 progetti di Roberto richiede copia/incolla di codice nella chat. Con il bridge:

- Claude può leggere/scrivere file dei progetti, fare git operations, eseguire test
- Il tutto con audit log, rate limit, deny list di sicurezza
- Tu mantieni il controllo: ogni progetto opt-in, write disabilitato di default
- Funziona da qualsiasi client MCP (claude.ai, Cursor, Cline, ecc.)

**Obiettivo secondario, ma reale:** imparare a costruire questa classe di sistemi, non solo a usarli. Esercizio formativo dichiarato.

---

## Owner

- **Roberto Novara** (`Pl1n10` / `robnovara@gmail.com` / `claudionetbackup@gmail.com`)
- Progetto personale, fuori orario Mauden, infrastruttura homelab personale.

---

## Stato a oggi

**Aprile 2026 — 7 di 12 step completati**, suite 237 test verdi.

| Step | Componente | Stato |
|------|-----------|-------|
| 1 | Skeleton repo | ✅ |
| 2 | `config.py` | ✅ |
| 3 | `auth.py` | ✅ |
| 4 | `security/{paths,commands,env}.py` | ✅ |
| 5 | `audit.py` | ✅ |
| 6 | `tools/filesystem.py` | ✅ |
| 7 | `server.py` (FastMCP + middleware) | ✅ |
| 8 | `tools/git.py` | ⏳ next |
| 9 | `tools/execution.py` | pending |
| 10 | `tools/system.py` | pending |
| 11 | `install.sh` (deploy) | pending |
| 12 | Documentazione finale | pending |

Stima residua: 4-6 ore di lavoro effettivo, spalmate.

---

## Architettura (sintesi)

```
claude.ai (cloud Anthropic)
    │ HTTPS
    ▼
mcpdev.robertonovara.me  ──►  Cloudflare Tunnel  ──►  devbox:8765 (devbox-bridge, FastMCP)
                                                            │
                                                            ▼
                                                     /home/hypn0/projects/<14 progetti>
```

Pianificato (post-MVP):
- **Cloudflare Access** davanti al tunnel come secondo layer auth
- Eventuale **`homelab-bridge`** separato per Gitea/Woodpecker/Harbor/k3s quando saranno deployati in "Casa B"

---

## Scelte architetturali chiave

Decisioni prese che vale la pena ricordare a sé stessi quando si torna sul progetto.

### Sicurezza
- **Whitelist mode su tutto:** progetti opt-in, write disabilitato di default, comandi via regex whitelist + tokenize-and-check su `rm`/`chown`/`chmod`/`dd`/`mv`.
- **Rate limit dopo auth success**, non prima — evita DoS-via-auth-spam su token validi.
- **Single-tenant assumption:** filesystem dei progetti sotto utente `hypn0`, niente symlink ostili.
- **TOCTOU accettato come limite documentato**, non risolto (richiederebbe `openat`+`RESOLVE_BENEATH`).

### Sviluppo
- **TDD red-green** su moduli di sicurezza (commands.py refattorizzato dopo che i test "red" hanno catturato bypass su `rm -rf`).
- **Diff preview obbligatoria** prima dell'apply per `auth.py`, `security/*`, `server.py`.
- **Auto-commit** a step verde (pytest + ruff + mypy passano).
- **`Co-Authored-By: Claude`** sui commit per trasparenza.
- **HANDOFF.md committato** e aggiornato a ogni step.

### Deploy
- **No GitOps fino al post-MVP:** prima il bridge funziona localmente, poi va su git su Gitea (quando esisterà).
- **Cloudflare Tunnel + DNS pubblico:** scelti perché Anthropic raggiunge l'MCP server dal cloud, non dalla tailnet del cliente.
- **Tailscale per servizi interni:** quando arriveranno Gitea/Woodpecker/Harbor (Casa B), parleranno via Tailscale tra loro.

---

## Decisioni esplicitamente NON prese (rinviate)

Cose che sono state discusse e rimandate a dopo l'MVP. Tienile presenti perché torneranno.

- **Cloudflare Access OAuth** davanti al tunnel — pianificato, non urgente per MVP.
- **`homelab-bridge` per Gitea/Woodpecker/Harbor/k3s** — dipende dal deploy della "Casa B" che ancora non c'è.
- **Multi-token / multi-utente:** oggi 1 token per Roberto. Se domani servisse un secondo client (es. Cursor sul laptop), basta generare un secondo token, lo schema regge.
- **Migrare il rate limit a Redis:** solo se single-process diventa limitante. Per ora no.
- **Workers > 1 di uvicorn:** per ora 1 (richiesto dal rate limiter in-memory).
- **Read-replica di audit log su rete:** out of scope.

---

## Rischi attivi

| Rischio | Probabilità | Impatto | Mitigazione |
|---------|-------------|---------|-------------|
| FastMCP API instabile (libreria giovane) | media | medio | Versione **pinnata esatta** in `pyproject.toml` + lockfile |
| Bug introdotto in `server.py` step 7 bypassa security | bassa | alto | Diff preview obbligatoria + review approfondita + test integrazione |
| Cloudflare Tunnel non passa correttamente `X-Forwarded-For` | media | medio | Test manuale post-deploy, fallback a `request.client.host` |
| Roberto non finisce il progetto e resta in canna | media | basso | HANDOFF aggiornato, riprendibile in qualunque momento; il valore formativo è già acquisito |
| Devbox down → bridge offline | bassa | basso (uso personale) | Accettato. Niente HA per ora. |

---

## Cosa farà il bridge nel concreto, quando finito

Esempi d'uso reali, una volta connesso a claude.ai:

1. **"Fai partire i test su sidebiz-agent e dimmi se passano"** → Claude chiama `run_tests("sidebiz-agent")`, riceve output troncato, riassume.
2. **"Mostrami lo stato git di control-room e fai il diff dei file modificati"** → `git_status` + `git_diff`.
3. **"Cerca tutti i `TODO` nei progetti Python e raggruppali per progetto"** → `search_files` su ogni progetto Python in iterazione.
4. **"Apri il file `auth.py` di devbox-bridge e applica questo refactor"** → `apply_patch` con `old`/`new`, audit log emesso.
5. **"Crea un branch `fix/cors` su frutta-verdura, applica le modifiche, committa"** → `git_create_branch` + `apply_patch` + `git_commit`.

NB: non è progettato per "fare deploy in produzione automatici". È progettato per **collaborazione fluida** mantenendo l'umano nel loop.

---

## Cosa il bridge NON farà mai

Per evitare scope creep e ricordartelo quando avrai la tentazione:

- ❌ Eseguire `git push --force` o operazioni distruttive irreversibili
- ❌ Permettere `kubectl apply` o modifiche dirette su cluster k3s (quello è GitOps via Woodpecker)
- ❌ Esporre `EvoTrader` per emissione ordini reali (sempre dry-run)
- ❌ Esporre `Robo-PAC` per esecuzione reale di trade
- ❌ Eseguire qualsiasi comando non in whitelist o in deny list (anche se l'utente insiste)
- ❌ Loggare token plain, password, secret values negli audit log
- ❌ Funzionare senza autenticazione (no anonymous mode, mai)

---

## Definition of Done — MVP

L'MVP si considera chiuso quando **tutte** queste condizioni sono vere:

- [ ] Tutti gli step 1-12 committati su `main`
- [ ] Suite test ≥ 95% verde, coverage moduli sicurezza ≥ 90%
- [ ] `install.sh` testato su devbox da zero (user pulito, niente preesistenze)
- [ ] Server avviabile via `systemctl start devbox-bridge`
- [ ] `cloudflared` configurato per `mcpdev.robertonovara.me`
- [ ] Custom connector registrato su claude.ai e funzionante
- [ ] Almeno 1 dei 14 progetti reali (probabilmente `sidebiz-agent`) abilitato in config con test command funzionante
- [ ] Test end-to-end manuale: "da claude.ai, lancia i test di sidebiz-agent e dimmi se passano"
- [ ] `SECURITY.md`, `SETUP.md`, `TOOLS.md` completi
- [ ] `FAILURES.md` con tutte le scelte di non-implementazione motivate

---

## Definition of Done — V1 (post-MVP, opzionale)

V1 è "il bridge è davvero pronto da affidare a sé stessi senza pensarci". Aggiunge:

- [ ] Cloudflare Access OAuth davanti al tunnel
- [ ] Audit log esportabile (rsync notturno verso storage esterno)
- [ ] Backup automatico di `/etc/devbox-bridge/token.sha256`
- [ ] Healthcheck endpoint pubblico (read-only) per uptime monitoring
- [ ] Almeno 5 dei 14 progetti reali configurati e testati end-to-end

---

## Lessons learned (da accumulare strada facendo)

Spazio per nota personale: cosa stai imparando facendo questo progetto, che potrai riusare altrove.

- **TDD red-green su deny list:** scrivere prima i test che catturano un bypass, vedere fallire il regex monolitico, refactorare a tokenize-and-check. È il workflow giusto su codice di sicurezza.
- **Whitelist > deny list per env e progetti:** sempre. Più stretto, fail-secure.
- **`shlex.split` + tokenize batte regex monolitica** per validare comandi shell multi-arg.
- **Audit log come schema fisso JSON:** o lo è, o è inutile in un incidente.
- **Diff preview obbligatoria** sui moduli critici evita rifacimenti costosi.
- **HANDOFF.md committato** rende il progetto riprendibile a freddo. Vale lo sforzo.
- **"Codice morto" = canary di scaffolding senza sostanza:** se vedi una costante definita ma mai usata in modulo di sicurezza, qualcosa non torna.

---

## Riferimenti

- **Repo:** `/home/hypn0/projects/devbox-bridge` (privato, no remote per ora)
- **Stato tecnico dettagliato:** `./HANDOFF.md`
- **Convenzioni di lavoro:** `./CLAUDE.md` (locale al repo) + `~/.claude/CLAUDE.md` (globale)
- **Decisioni di non-implementazione:** `./FAILURES.md`
- **Threat model + audit schema:** `./docs/SECURITY.md`
- **Setup deploy:** `./docs/SETUP.md` (in stato skeleton, completare a step 12)
- **Reference tool MCP:** `./docs/TOOLS.md` (idem)

Conversazioni Claude.ai principali su questo progetto: cercare con `conversation_search` su "devbox-bridge" o "MCP server".
