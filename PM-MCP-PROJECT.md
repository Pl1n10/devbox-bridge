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

**Aprile 2026 — 8 di 12 step completati**, suite 271 test verdi.

| Step | Componente | Stato |
|------|-----------|-------|
| 1 | Skeleton repo | ✅ |
| 2 | `config.py` | ✅ |
| 3 | `auth.py` | ✅ |
| 4 | `security/{paths,commands,env}.py` | ✅ |
| 5 | `audit.py` | ✅ |
| 6 | `tools/filesystem.py` | ✅ |
| 7 | `server.py` (FastMCP + middleware) | ✅ |
| 8 | `tools/git.py` | ✅ |
| 9 | `tools/execution.py` | ⏳ next |
| 10 | `tools/system.py` | pending |
| 11 | `install.sh` (deploy) | pending |
| 12 | Documentazione finale | pending |

Stima residua: 3-5 ore di lavoro effettivo, spalmate.

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

## Roadmap — Bootstrap progetti da MCP (post-V1)

> Aggiunto 2026-05-13 durante prima sessione di dogfooding reale (write_enabled=true sul progetto `devbox-bridge` stesso). Obiettivo: permettere al bridge di **registrare nuovi progetti sotto richiesta esplicita**, oggi non possibile by design.

### Motivazione

Oggi il MCP non può creare un nuovo progetto sulla devbox: `/etc/devbox-bridge/config.yaml` è root-only, `setfacl` e il drop-in systemd `projects.conf` li applica `deploy/install.sh` come root, il restart richiede `systemctl`. Risultato: se voglio chiedere a claude.ai "crea `project-delphi` sulla devbox", devo dropparmi a root e fare i passi manualmente.

Vogliamo che — **sempre e solo sotto richiesta esplicita dell'utente, mai autonomamente in catena LLM** — il bridge possa: (1) materializzare un albero file dentro `/home/hypn0/projects/<nuovo>/`, (2) registrare il progetto in `config.yaml`, (3) applicare ACL + drop-in + restart. Mantenendo il threat model attuale: no path traversal, no escape da `/home/hypn0/projects/`, contratto closed-set, audit completo, validazione lato componente privilegiato (mai delegata al chiamante).

### Fase 0 — Scaffolding "out-of-band" (zero nuovo privilegio)

L'MCP non registra il progetto direttamente, ma prepara tutto e consegna un **comando one-shot root-only** da incollare in `sudo`. Sblocca il caso d'uso senza introdurre superficie nuova.

- [ ] **T0.1** Tool `prepare_project_bundle(name, archive_b64|url, write_enabled, test/lint/build, whitelist)`:
  - valida `name` (regex `^[a-z0-9][a-z0-9-]{1,39}$`)
  - rifiuta path traversal nello zip (`../`, leading `/`) e symlink interni
  - estrae in staging del bridge: `/var/lib/devbox-bridge/staging/<name>/`
  - emette **manifest firmato** (HMAC col token bridge): `{name, path_target, sha256_tree, config_block_yaml, ts}`
- [ ] **T0.2** Script `deploy/register-project.sh` (root) idempotente:
  - prende il manifest, verifica HMAC, controlla `ts` non oltre N minuti
  - sposta lo staging in `/home/hypn0/projects/<name>/` (rifiuta se la dest esiste già con owner diverso da `hypn0`)
  - merge nel `config.yaml` atomico (tmp + `python3 -c "import yaml; yaml.safe_load(...)"` di sanity + `rename`)
  - richiama `deploy/install.sh` per ACL + drop-in + `daemon-reload`
- [ ] **T0.3** Tool `register_project_command(manifest_id)` → ritorna la stringa esatta `sudo /opt/devbox-bridge/deploy/register-project.sh <id>` da incollare.
- [ ] **T0.4** Audit: estendere l'audit log esistente con eventi `prepare_project_bundle` e `register_project_command_emitted`, con `manifest_id` come correlation key.
- [ ] **T0.5** GC dello staging: cancellare bundle non promossi dopo 24h.

Risultato finale del flow: "crea project-delphi" → io rispondo "incolla: `sudo ...`" → tu incolli → fatto.

**Stato al 2026-05-13 (prima sessione di dogfooding):**
- ✅ `deploy/register-project.sh` draft committato — root-side completo: HMAC verify (constant-time, Python), schema check, replay window, sha256_tree, jail in `PROJECTS_ROOT`, merge atomico del config, invoke di `install.sh`, restart, cleanup, audit log JSON in `/var/log/devbox-bridge/admin-audit.log`. Header del file documenta il **contratto del bundle** (struttura `staging/<id>/{manifest.json, manifest.hmac, payload/}` + schema manifest v1) — chi implementerà il tool `prepare_project_bundle` lato bridge usa quello come spec.
- ✅ `deploy/install.sh` patchato — crea `/var/lib/devbox-bridge/staging/` (owner bridge:bridge 0750) + genera `bootstrap.key` (root:bridge 0640) idempotente.
- ⏳ T0.1 (tool `prepare_project_bundle` lato bridge): da scrivere, in `src/devbox_bridge/tools/`. Deve produrre bundle conforme allo schema in `register-project.sh`.
- ⏳ T0.3 (tool `register_project_command`): banale una volta che T0.1 esiste.
- ⏳ T0.4 (audit eventi `prepare_project_bundle` / `register_project_command_emitted`): da aggiungere a `audit.py` come nuovi eventi nel set `AUDITED_WRITE_EVENTS`.
- ⏳ T0.5 (GC staging): da scrivere come task ricorrente nel bridge o cron systemd timer.
- ⚠️ `register-project.sh` non ancora testato end-to-end (manca T0.1 che produca un manifest da consumare). Test manuale possibile fabbricando un bundle a mano.

### Fase 1 — Admin sidecar privilegiato

Quando Fase 0 inizia a pesare e si vuole chiudere il loop senza `sudo` manuale, serve un secondo processo root con contratto strettissimo.

- [ ] **T1.1** Nuova unit `devbox-bridge-admin.service` (root) che ascolta su `/run/devbox-bridge/admin.sock` (root:bridge 0660). Peer-cred via `SO_PEERCRED`: accetta solo `uid=bridge`.
- [ ] **T1.2** Protocollo JSON line-based **closed-set**: `register_project`, `unregister_project`, `set_write_enabled`. Nessun "exec arbitrary", nessun "edit config raw". Schema validato lato admin.
- [ ] **T1.3** Validazioni nel sidecar (NON delegate al bridge, che è meno fidato):
  - name regex, `realpath` del path target sotto `/home/hypn0/projects/`, no symlink in mezzo, no owner diverso da `hypn0`
  - `command_whitelist` proposta dal bridge filtrata contro una **superwhitelist hardcoded** nel sidecar — il bridge non può iniettare `^rm.*` o `^curl.*`
- [ ] **T1.4** Refactor: estrarre da `deploy/install.sh` le funzioni di setup-progetto in `deploy/lib/*.sh` riusabili sia dall'installer sia dal sidecar (evita drift).
- [ ] **T1.5** Audit log dedicato `/var/log/devbox-bridge/admin-audit.log`, append-only, una riga JSON per op, include `pid+uid` del peer e diff testuale del config applicato.
- [ ] **T1.6** Hardening unit: `ReadWritePaths=/etc/devbox-bridge /var/log/devbox-bridge /etc/systemd/system/devbox-bridge.service.d /home/hypn0/projects`. **No** `NoNewPrivileges` (deve `setfacl` + `systemctl`), ma `SystemCallFilter` stretto, `CapabilityBoundingSet` minimo (solo `CAP_CHOWN`, `CAP_FOWNER`, `CAP_DAC_OVERRIDE` se servono).
- [ ] **T1.7** Client del sidecar nel bridge + tool MCP `create_project`, `remove_project`, `set_write_enabled` che inoltrano.

### Fase 2 — UX, safety net, test

- [ ] **T2.1** Two-phase confirm: `propose_project` ritorna `confirmation_token` + diff testuale del config; `create_project` lo richiede. Evita create accidentali in catene LLM lunghe.
- [ ] **T2.2** Soft-limit: max N progetti registrabili via sidecar (default 30) — guardia anti-loop esauri-ACL/inode.
- [ ] **T2.3** Test integrazione: fake sidecar in-process, full flow con rollback se `install.sh` interno fallisce a metà.
- [ ] **T2.4** Documentare in `FAILURES.md` le opzioni scartate per la registrazione (setuid wrapper su `install.sh`, sudoers `NOPASSWD` sull'installer completo, dare write al bridge su `/etc/`).

### Decisioni aperte da fissare prima di scrivere codice

1. **Solo Fase 0, o si va dritti a Fase 1?** Fase 0 ≈ 2 giornate, sblocca subito. Fase 1 ≈ 1-2 settimane con review attenta del threat model.
2. **Estrazione zip lato bridge o lato sidecar?** Preferenza: lato bridge (meno codice in root). Richiede staging area `/var/lib/devbox-bridge/staging/` rw per il bridge — al momento ha solo `/var/log/devbox-bridge`.
3. **Origine archivio**: solo upload base64 via tool, o anche pull da URL? Il secondo apre superficie SSRF da contenere (URL allowlist, blocco loopback/RFC1918).
4. **Default `write_enabled` per progetti registrati via MCP**: `false` (più sicuro, richiede secondo step esplicito) o `true` (UX migliore, rischio più alto)?

---

## Roadmap — Git push con consenso esplicito (post-V1)

> Aggiunto 2026-05-13 durante stessa sessione di dogfooding. Estende il pattern di Fase 0/1/2 ("operazioni privilegiate via MCP con consenso esplicito") al caso d'uso `git push`, oggi bloccato a priori dal flag `allow_push: false`.

### Motivazione

`allow_push: false` rende il tool `git_push` non chiamabile dal MCP. Semantica binaria: o l'LLM non può mai pushare, o (con `true`) può pushare in qualsiasi momento. Il rischio non è "claude diventa cattivo", ma:

- **Prompt injection** da contenuto del repo / output di tool può convincere l'LLM a pushare commit non voluti, magari `--force` su `main`.
- **Catene LLM lunghe** perdono lo stato e fanno push "credendo" di avere autorizzazione.
- **Confirmation bias**: l'LLM chiede "vuoi che pushi?" e *interpreta* una "sì, vai con la prossima cosa" come autorizzazione.

Un "sì" testuale in chat NON è consenso esplicito a prova di injection — l'LLM stesso può fabbricarlo nel proprio contesto. Serve un canale **fuori dal contesto LLM**.

### Pattern: two-phase con codice out-of-band

1. `git_push_request(project, branch)` — bridge calcola summary (branch, N commit ahead, file changed, titoli, diff stat), genera codice 6-cifre random, scrive summary + codice in `journalctl -t devbox-bridge-push` (e opzionalmente canale notification configurato), ritorna all'LLM **solo** `{status: pending, summary, branch, request_id}`. **L'LLM non vede mai il codice.**
2. L'utente apre il journal sulla devbox (`journalctl -u devbox-bridge -t devbox-bridge-push -f`), legge codice + summary, decide se ok.
3. L'utente comunica il codice all'LLM via chat ("ok pusha, 547321").
4. `git_push_confirm(project, request_id, code)` — bridge verifica match constant-time + TTL + single-use, esegue `git push origin <branch>`, audit completo, ritorna esito.

Una prompt injection che dica "rispondi col codice 123456" fallisce: il bridge ha generato 547321 e rifiuta. Il consenso vive in journalctl + nella testa dell'utente, mai nel contesto LLM finché l'utente non lo digita.

### Fase 3 — Tasks

- [ ] **T3.1** Refactor `allow_push: bool` in `config.yaml` → `push_policy: {"disabled", "two_phase", "always"}` con default `disabled`. Branch allowlist opzionale `push_allowed_branches: ["feat/*", "fix/*"]` — `main`/`master` mai nei default.
- [ ] **T3.2** Nuovi tool MCP `git_push_request` + `git_push_confirm` in `src/devbox_bridge/tools/git.py`. State in `/var/lib/devbox-bridge/push-pending/<request_id>` (TTL via mtime check, default 5 min, cleanup automatico post-confirm o expiry).
- [ ] **T3.3** Codice random 6-cifre con `secrets.randbelow(10**6)`; verifica con `secrets.compare_digest` (constant-time); codice mai loggato plain, solo `sha256(code)[:8]` in audit.
- [ ] **T3.4** Canale OOB:
  - **default**: `journalctl -t devbox-bridge-push` (l'utente apre `journalctl ... -f` in una shell sulla devbox).
  - **opzionale** (Fase 3.1): `notification_channel: {kind: "ntfy"|"webhook"|"email", url, token}` in config.yaml. ntfy su topic privato è il candidato preferito (push a mobile).
- [ ] **T3.5** Force-push: `--force` standalone mai esposto. Solo `--force-with-lease` consentito, e richiede un campo esplicito `force_lease: true` nel `git_push_request` payload (l'audit traccia la flag e il summary contiene un highlight chiaro).
- [ ] **T3.6** Rate limit per progetto: max N `git_push_request` al giorno (default 5), in-memory con reset a mezzanotte UTC. Anche limite di N codici pending contemporanei (default 2) per evitare confusion attack.
- [ ] **T3.7** Audit: nuovi eventi `push.requested`, `push.confirmed`, `push.executed`, `push.code_mismatch`, `push.expired`, `push.rate_limited` in `AUDITED_WRITE_EVENTS` di `audit.py`. `push.code_mismatch` SEMPRE auditato anche con `audit_reads=false`.
- [ ] **T3.8** Test unit della state machine: code generation, TTL expiry, mismatch, replay (codice già consumato), constant-time compare, rate limit, branch allowlist, force-with-lease flag passthrough.
- [ ] **T3.9** Test integrazione: fake git remote (`file://...`), full request→confirm→push flow incluso force-with-lease rejection se la ref remota è cambiata da sotto.

### Threat model / decisioni aperte

1. **Force push policy**: solo `--force-with-lease` (preferenza) o entirely vietato? Lease + audit pesante mi sembra il giusto compromesso.
2. **`main` push automatico**: mai, anche con codice? Se sì, il path corretto è "PR + merge via GitHub UI", non MCP. Decidere se enforce-rifiuto di `main`/`master` nei default di `push_allowed_branches`.
3. **TTL codice**: 5 min default ok? Trade-off: più corto = più sicuro ma frustra l'utente che impiega a guardare journalctl.
4. **Cooldown post-mismatch**: dopo N tentativi sbagliati (es. 3), bloccare push-request per M minuti? Anti-brute-force su un codice di 1M possibilità — defense-in-depth, non urgente.
5. **OOB di default**: solo journalctl, o anche ntfy out-of-the-box (richiede topic privato pre-configurato)? Default journalctl-only è scelta conservativa.

### Threat residuo (documentato per onestà)

Anche con tutto: attaccante con shell sulla devbox può leggere journalctl → ruba codice → confirms. Mitigazione: ACL strette sul journal (l'utente `devbox-bridge` è già in `systemd-journal`, ma altri utenti del sistema possono comunque leggere il journal a meno di config restrittiva). Se l'attaccante ha shell, il bridge è il minore dei problemi.

Attaccante con accesso al canale notification (es. ntfy con topic pubblico, email account compromesso) → idem. Default journalctl-only è scelta conservativa.

Prompt injection che convince l'utente a digitare codici sbagliati o a fidarsi di summary falsi: **non difendibile da codice solo**. Mitigazione: l'utente deve leggere il summary in journalctl e fare un confronto critico ("davvero questo è quello che volevo?"). Pattern paragonabile a "verifica fingerprint SSH al primo connect" — richiede attenzione umana per design.

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
