# SECURITY — Threat model

> Stato MVP (step 1-12 chiusi). Threat model e audit di tutti i componenti
> implementati sono documentati: auth bearer + rate limit (step 3),
> validazione path/comandi/env (step 4), audit log JSON Lines con
> rotazione/retention (step 5), backstop dei tool git (step 8), gating
> exec su `write_enabled` + deny list su comandi configurati (step 9),
> whitelist path/unit per i tool sistema con semantica fail-secure (step
> 10), hardening systemd + ACL chirurgiche da `config.yaml` (step 11).

## Difese in serie

Il bridge applica difese **in cascata, non ridondanti**: ogni livello
copre una superficie diversa, e tutti devono cedere perché un'azione non
autorizzata vada a buon fine. La tabella elenca cosa blocca ciascun
livello e cosa **non** è suo compito (le entry "non blocca" non sono
buchi: sono delegazioni esplicite a un altro layer).

| # | Layer | Implementazione | Blocca | Non blocca (per design) |
|---|---|---|---|---|
| 1 | Network ingress | Cloudflare Tunnel + (opz.) Cloudflare Access | Esposizione pubblica diretta della porta 8765; (con Access) accesso anonimo | Brute-force token a livello applicativo (vedi 2-3) |
| 2 | Auth bearer | `auth.Authenticator` (`hashlib.sha256` + `hmac.compare_digest`) | Token mancante / invalido / scaduto | DoS-via-token-spam (vedi 3) |
| 3 | RateLimiter | `auth.RateLimiter` sliding-window 60/min per token+IP | Burst di chiamate da un client autenticato | Brute-force di token invalidi (token errati NON consumano il bucket per design — vedi `Rate limit → Token invalidi NON consumano il rate limit` per il razionale) |
| 4 | Project gate | `config.projects[*].write_enabled` / `allow_push` | Scritture su progetti non opt-in; push su progetti senza `allow_push` | Scritture *dentro* un progetto opt-in (granularità per-file non esiste) |
| 5 | Path validation | `security/paths.py` (`resolve_within`, `resolve_within_any`) | Traversal `..`, simlink che escono, path assoluti fuori, glob malformati | TOCTOU (single-tenant, accettato — vedi `HANDOFF.md`) |
| 6 | Command validation | `security/commands.py` (deny list + tokenize-and-check + regex whitelist) | Pattern distruttivi noti, comandi non in whitelist | Comandi semantically-malicious che matchano una whitelist troppo permissiva |
| 7 | Env sanitizer | `security/env.sanitize_env()` whitelist-mode | Leak di `*_TOKEN`, `*_SECRET`, `*_KEY`, `AWS_*`, `LD_PRELOAD`, `PYTHONPATH` non opt-in | Variabili in `env_passthrough` esplicito (deroga dichiarata, audit-warned) |
| 8 | Subprocess hardening | `subprocess.run(shell=False, stdin=DEVNULL)` + `cwd=project_root` | Shell injection via metachar; ereditarietà stdin; escape dal cwd | Bug nel comando configurato dall'operatore |
| 9 | systemd hardening | `deploy/devbox-bridge.service` + drop-in `ReadWritePaths` | Scrittura kernel-level su path non opt-in (anche se il check applicativo cedesse), exec di nuovi binari, accesso a `/home/hypn0` user files | Bug semantici dentro i path scrivibili dichiarati |
| 10 | Audit log | `audit.AuditLogger` JSON Lines + rotazione + sanitizzazione | Rumore non-strutturato, leak di token plain o path sensibili | Detection real-time (è log post-hoc, non IDS) |

I livelli (4)+(9) sono **complementari**, non ridondanti: il check
applicativo `write_enabled` è una difesa logica; il `ReadWritePaths` di
systemd è un bind mount kernel-level. Anche se un baco bypassasse il
primo, il filesystem nel namespace del servizio resterebbe read-only
sui progetti non opt-in. `setfacl` da solo non basterebbe perché
systemd lo bypassa via namespace; le due difese sono complementari.

## Cosa devbox-bridge protegge

- Path traversal fuori dai progetti whitelisted
- Shell injection (no `shell=True`, whitelist regex con fullmatch, deny list hardcoded)
- Token brute-force (compare_digest + rate limit 60/min)
- Leak di secret via env (sanitizer rimuove `AWS_*`, `*_TOKEN`, `*_SECRET`, `*_KEY`)
- Comandi distruttivi noti (deny list hardcoded: `rm -rf`, `dd if=`, fork bomb, curl|sh, ...)
- Accesso HTTP anonimo al server MCP: ogni richiesta HTTP passa dal middleware
  bearer prima di arrivare a FastMCP.

## Cosa devbox-bridge NON protegge

- Se imposti `write_enabled: true` su un progetto, Claude può scrivere qualsiasi file
  dentro quel progetto. Non c'è un secondo livello di approvazione per file.
- Se aggiungi `^.*$` o pattern troppo permissivi alla whitelist comandi, perdi
  la protezione del whitelisting (la deny list resta come backstop, ma è limitata).
- Se `allow_push: true`, Claude può pushare su qualsiasi remote configurato.
- I file letti via `read_file` finiscono in chiaro nella conversazione claude.ai.

## Mitigazioni a livello deploy

- **User dedicato `devbox-bridge`** (no-login, no sudo). Membership
  `systemd-journal` per `read_journalctl`; **NON** `adm` (least
  privilege: `adm` darebbe accesso anche a `/var/log/syslog`,
  `/var/log/auth.log`, ecc. che il bridge per design non tocca). Vedi
  `HANDOFF.md → Permessi journal`.
- **systemd hardening** (`deploy/devbox-bridge.service`):
  `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome=read-only`,
  `MemoryDenyWriteExecute`, `RestrictAddressFamilies=AF_UNIX AF_INET
  AF_INET6`, `SystemCallFilter=@system-service ~@privileged @resources`,
  `PrivateTmp/Devices`, `LockPersonality`, `ProtectProc=invisible`,
  `LimitNOFILE=4096`, `TasksMax=256`. Capabilities all-drop.
- **Drop-in `ReadWritePaths`** (`/etc/systemd/system/devbox-bridge.service.d/projects.conf`):
  `ReadWritePaths=` derivato da `config.yaml` — solo i progetti opt-in
  (`write_enabled: true`) sono scrivibili nel namespace del servizio.
  Drop-in **rigenerato da zero a ogni `install.sh`**, anche vuoto se
  zero progetti rw, per evitare entry stale su downgrade rw→ro.
- **ACL chirurgiche** sui progetti (`setfacl -R -m u:devbox-bridge:r-X`
  o `rwX` + default ACL). Probe attivo (`setfacl`+`getfacl` su
  `mktemp`) — NON grep su mount options, falserebbe negativo su ext4
  Ubuntu 24.04 dove `acl` è on-by-default e non compare in `mount`.
- **Cloudflare Access** davanti al tunnel come 2° fattore (consigliato,
  vedi `SETUP.md`).
- **Audit log** su file separato per ogni azione write/exec, fuori dal
  bind mount dei progetti (`/var/log/devbox-bridge`, owned by service
  user, `0750`).

## Rate limit — proprietà e limiti

Il rate limit (60 chiamate/min per token) è implementato in-memory in
`auth.RateLimiter`. Tre proprietà da conoscere:

1. **Reset al restart del server.** Un crash o un `systemctl restart devbox-bridge`
   azzera il bucket. Accettabile: il restart è già un evento raro, e Cloudflare
   Tunnel + Cloudflare Access aggiungono un secondo layer di throttling.
2. **Per-worker, non globale.** Funziona correttamente solo con singolo worker
   uvicorn. Se in futuro si scala a `--workers N`, il limite diventa N×60/min
   effettivo. Il deploy systemd attuale usa worker singolo.
3. **Non persiste tra crash.** Il bucket vive solo in memoria del processo.

Non è un bug: scelta consapevole di semplicità. Evoluzione naturale, se servisse:
Redis o Cloudflare Rate Limiting davanti al tunnel.

### Token invalidi NON consumano il rate limit

Il rate limiter viene applicato **dopo** la verifica del token. Un attaccante che
spara migliaia di token random verso `mcpdev.robertonovara.me` (DNS pubblico) NON
satura il bucket di un token valido. Razionale:

- Token random da 32 byte = 2²⁵⁶ spazio di ricerca → brute-force non-issue cripticamente.
- Difesa in profondità extra (rate limit anche su auth fail, lockout per IP, ecc.)
  la mette **Cloudflare Access** davanti al tunnel, non in-app.
- Lasciare il bucket in-app vulnerabile a "auth-spam DoS" sarebbe un buco logico.

## Integrazione HTTP/FastMCP

`server.py` espone FastMCP tramite transport HTTP su `/mcp`.

### Auth middleware

Il middleware ASGI `BearerAuthMiddleware` controlla tutte le richieste HTTP:

- legge `Authorization: Bearer <token>`;
- valida il token con `Authenticator`;
- applica il rate limit solo dopo auth success;
- in caso di token mancante o invalido risponde `401` con body generico
  `unauthorized`;
- in caso di rate limit risponde `429` con header `Retry-After: 60`.

Il client non riceve mai il motivo dettagliato del fallimento auth. Il motivo
rimane solo nei log/audit server-side.

### Client IP

Per audit e rate-limit context:

1. usa il primo valore di `X-Forwarded-For`, ad esempio `ip1` da
   `ip1, ip2, ip3`;
2. se manca, usa `request.client.host`;
3. valida con `ipaddress.ip_address`;
4. se il valore non e un IP valido, usa `client_ip="(invalid)"` e prosegue.

### Mapping errori tool

Il server mantiene i tool filesystem puri e aggiunge audit nel wrapper FastMCP.

Mapping attuale:

- `PathSecurityError`, `GlobSecurityError`, `WriteNotAllowedError` →
  `event="path.rejected"`, `outcome="denied"`;
- `PushNotAllowedError` (git tool su progetto con `allow_push=false`) →
  `event="tool.git_push"`, `outcome="denied"` (è una policy di tool, non
  un'errore di path);
- altre eccezioni tool → `event="tool.<name>"`, `outcome="error"`;
- success → `event="tool.<name>"`, `outcome="success"`.

`AuditLogger.should_audit()` decide se scrivere effettivamente l'evento. Quindi
i read (`read_file`, `list_projects`, `list_directory`, `search_files`) restano
silenziosi con `audit.audit_reads=false`, mentre write e reject vengono sempre
scritti.

## Audit logging

Ogni azione write/exec, ogni fallimento di auth e ogni reject di sicurezza
viene loggato in `<log_dir>/audit/audit.log` (JSON Lines, un evento per riga).

### Schema fisso

Ogni linea ha lo stesso set di campi (alcuni `null` se non applicabili):

```json
{
  "timestamp": "2026-04-28T14:23:45.123Z",
  "event": "tool.write_file",
  "outcome": "success",
  "token_id": "a1b2c3d4",
  "client_ip": "100.64.x.x",
  "project": "sidebiz-agent",
  "tool": "write_file",
  "args_summary": {"path": "src/foo.py", "bytes": 1234, "content_sha8": "deadbeef"},
  "duration_ms": 42.0,
  "error_class": null,
  "error_message": null
}
```

`outcome ∈ {success, denied, error}`. Schema fisso = grep-able, parsabile,
alerting facile.

`outcome_detail` (top-level opzionale, popolato solo per i tool exec) è
documentato in `TOOLS.md → outcome_detail audit`. Valori:
`completed`/`nonzero_exit`/`timed_out`. Non promosso a `outcome="error"`
perché il bridge ha eseguito il subprocess correttamente; il dettaglio
descrive cosa è successo nel processo figlio.

#### Versioning dello schema

Lo schema **non ha un campo `schema_version`**. Scelta consapevole, non
dimenticanza: l'MVP single-tenant non ha consumer downstream
(parser, alerting, dashboard) da migrare in modo coordinato, e
introdurre un campo versionato senza un piano di evoluzione sarebbe
cargo cult.

**Conseguenza operativa: breaking changes dello schema audit sono
vietati senza un migration plan esplicito.** Aggiungere campi *opzionali*
(es. `outcome_detail` allo step 9) è non-breaking. Rinominare campi,
cambiare tipi o restringere domini di valori (es. allargare `outcome`)
richiede:

1. transition window con scrittura dual-format,
2. comunicazione ai consumer (oggi: solo `tail_log`/`read_journalctl`
   stessi tool del bridge — domani potrebbe essere uno script di
   alerting esterno),
3. introduzione di `schema_version` come parte stessa della migration.

Se la complessità cresce (multi-tenant, audit shipping out-of-box verso
un SIEM), `schema_version` va aggiunto **prima** del primo breaking
change, non dopo.

### Eventi auditati

Sempre loggati (override di `audit_reads`):
  - `auth.failed`, `auth.rate_limited`
  - `command.rejected`, `path.rejected`
  - Tutti i tool write/exec: `tool.write_file`, `tool.apply_patch`,
    `tool.git_commit`, `tool.git_push`, `tool.git_create_branch`,
    `tool.run_command`, `tool.run_tests`, `tool.run_lint`, `tool.run_build`
  - **Qualsiasi `outcome ∈ {denied, error}`** anche su tool read. Un
    denial o un errore è materiale forense, non rumore — `audit_reads=false`
    sopprime il volume delle read OK, non i fail. Implementato in
    `AuditLogger.log` (override esplicito su outcome non-success).

Loggati solo se `audit.audit_reads: true` in config (e `outcome="success"`):
  - `tool.read_file`, `tool.list_projects`, `tool.list_directory`,
    `tool.search_files`, `tool.git_status`, `tool.git_diff`, `tool.git_log`,
    `tool.git_branch_current`, `tool.tail_log`, `tool.read_journalctl`,
    `tool.list_systemd_services`, `tool.get_system_info`

Default `audit_reads: false` per evitare rumore — i read sono frequenti.

### Sanitizzazione (defense in depth)

`audit.py` applica una pass aggiuntiva di sanitizzazione su ogni evento,
DUPLICANDO la sanitizzazione che i tool fanno prima. È intenzionale:
l'audit è la "seconda riga" se un tool dimenticasse di sanitizzare.

Regole:
  - **Token plain mai loggato.** Si usa `token_log_id` da `auth.py`
    (= sha256(token)[:8]).
  - Chiavi che contengono (case-insensitive substring) `token`, `password`,
    `passwd`, `secret`, `api_key`, `apikey`, `private_key` →
    valore sostituito con `<redacted>`.
  - Path che contengono segmenti `.env`, `secrets`, `credentials`, `.aws`,
    `.ssh`, `.gnupg`, `.kube`, `.docker` → `<redacted-path>`.
  - Pass ricorsiva su dict/list annidati.
  - Helper `summarize_content(content)` per file: solo `{bytes, content_sha8}`.
  - Helper `summarize_command_output(output)` per stdout/stderr: head 500ch
    + tail 500ch + `total_sha8` + `total_bytes` + `truncated: bool`.

### Rotazione e retention

  - **Rotazione per size**: `rotation_size_mb` (default 50). Quando
    `audit.log` supera la soglia, viene rinominato (atomic rename POSIX su
    stesso fs), gzippato in `audit-YYYYMMDD-HHMMSS.log.gz`, e un nuovo
    `audit.log` viene aperto.
  - **Atomicity**: tutta la rotazione avviene sotto `threading.Lock` →
    nessun evento perso anche con scritture concorrenti.
  - **Retention**: `retention_days` (default 90). All'avvio del processo,
    i file `audit-*.log.gz` con `mtime` più vecchio di N giorni vengono
    eliminati.

### Configurazione

Tutto opzionale — il blocco `audit:` può essere omesso. Default:

```yaml
audit:
  log_dir: <server.log_dir>/audit  # se non specificato
  rotation_size_mb: 50
  retention_days: 90
  audit_reads: false
```

## Strategia deny list (security/commands.py)

La validazione comandi usa **due strategie distinte** in cascata, scelte in
base alla forma del comando:

### Tokenize-and-check (per comandi multi-argomento)

Per `rm`, `chown`, `chmod`, `dd`, `mv`, `kill`, `mkfs.*` la stringa viene
prima tokenizzata via `shlex.split()` e poi gli argomenti vengono ispezionati
posizionalmente. Questo è l'unico modo CORRETTO di validare comandi dove i
flag possono apparire in qualsiasi posizione e i path target possono essere
multipli.

**Esempi che un singolo regex monolitico NON catturerebbe** ma il
tokenize-and-check sì:

- `rm -rf / --verbose` (flag dopo path)
- `rm -rf / /tmp/foo` (path multipli, `/` non in coda)
- `rm -rf /etc`, `rm -rf /usr`, `rm -rf /boot`, `rm -rf /sys`, `rm -rf /proc`
- `chown -R user /etc --verbose` (flag dopo path)
- `dd if=x of=/etc/passwd`, `dd of=/boot/vmlinuz` (target di sistema non `/dev/`)
- `mv / /tmp/x`, `mv /home/projects /dev/null`

### Regex search (per costrutti sintatticamente fissi)

Per fork bomb, `curl|sh`, `wget|python`, redirect verso path di sistema,
`shutdown`/`reboot`/`poweroff`/`halt`/`init 0|6`/`systemctl poweroff|reboot|halt|emergency|rescue`
si usa `re.search()` sulla stringa intera. Questi costrutti hanno una forma
sintattica fissa per cui un singolo regex è sufficiente e robusto.

**Defense-in-depth note:** alcuni di questi pattern (curl|sh, redirect a path
di sistema) sono RIDONDANTI con il modello di esecuzione attuale
(`subprocess.run(shell=False)` rende `|` e `>` argomenti letterali). Sono
mantenuti come strato di protezione contro futuri regression che potrebbero
reintrodurre `shell=True`.

### Whitelist (per progetto)

Dopo la deny list, il comando deve matchare almeno un pattern in
`projects[<name>].command_whitelist` via `re.fullmatch` (anchor implicito).
Senza whitelist o senza match → reject. Questo impedisce ad esempio che
`pytest && rm -rf /` matchi un pattern `pytest` (perché fullmatch verifica
l'intera stringa).

## env_passthrough — deroga esplicita alla whitelist

`env_passthrough` (in `config.yaml` per progetto) è una **deroga esplicita** alla
policy di whitelist di `security/env.sanitize_env()`.

In whitelist mode, di default solo le variabili infrastrutturali (`PATH`,
`HOME`, `USER`, `LANG`, `LC_*`, ecc.) vengono propagate al subprocess. Tutto il
resto, incluso `LD_PRELOAD`, `PYTHONPATH`, `*_TOKEN`, `*_KEY`, `*_SECRET`,
`AWS_*` e qualsiasi altra variabile non riconosciuta, viene **droppato**.

Se metti `GITHUB_TOKEN` in `env_passthrough`, sai che stai esponendo quella
secret ai comandi del progetto. Usalo solo dove necessario (es. CI script che
pusha tag autenticato, test che parlano con un'API esterna sandbox).

**Audit:** ogni variabile in `env_passthrough` che matcha un `_SECRET_PATTERNS`
viene loggata come warning `env.passthrough.secret_match` con il nome della
var. Il passthrough resta valido — il warning serve solo a tracciare l'uso di
una deroga per review futura.

## Whitelist system tools — fail-secure su lista esplicitamente vuota

I tool read-only di sistema (`tail_log`, `read_journalctl`,
`list_systemd_services`) sono validati contro whitelist in
`config.system`. Le tre liste hanno semantica differenziata fra "sezione
omessa" e "lista esplicitamente vuota":

```yaml
# Caso A: sezione `system:` interamente omessa (o `system: {}`)
# → default permissivi onboarding-friendly
#   log_paths_whitelist:    [/var/log/devbox-bridge]
#   systemd_unit_whitelist: [devbox-bridge.service]
#   systemd_filter_default: "devbox-"

# Caso B: lista esplicitamente vuota
system:
  log_paths_whitelist: []         # → NESSUN path accessibile
  systemd_unit_whitelist: []      # → NESSUNA unit accessibile
```

Il default permissivo si applica **solo** in assenza totale di
configurazione (Caso A): è una scelta di onboarding. Una volta che
l'operatore ha messo mano alla sezione `system:`, una whitelist `[]`
viene rispettata letteralmente come "fail-secure: nessuna risorsa
accessibile". Riempire automaticamente una lista vuota in YAML
sarebbe fail-open — anti-pattern.

I default sono definiti come letterali in `config.py` solo
(`DEFAULT_LOG_PATHS_WHITELIST`, `DEFAULT_SYSTEMD_UNIT_WHITELIST`,
`DEFAULT_SYSTEMD_FILTER`); single source of truth.

### Path validation

`tail_log(path)` passa per `security.paths.resolve_within_any(path,
allowed_roots)`. Il check è **whitelist → esistenza** in quest'ordine:

- `path` deve essere **assoluto** (path relativi rifiutati con
  `PathSecurityError`).
- (a) `Path.resolve(strict=False)` normalizza `..` e segue symlink
  intermedi che esistono. Il path normalizzato viene matchato contro la
  whitelist. **Fuori whitelist → `PathSecurityError`**, anche se il
  file non esiste (vedi sotto, "info-leak").
- (b) Solo se la whitelist matcha, viene fatto `Path.resolve(strict=True)`
  per verificare l'esistenza. **Dentro whitelist ma inesistente →
  `FileNotFoundError`** (mappato su `LogPathNotFoundError`).
- (c) Defense-in-depth post-`strict=True`: il path effettivamente
  risolto viene **re-validato** contro la whitelist. Riduce la
  superficie TOCTOU contro symlink sostituiti tra il check (a) e
  l'`open()` del subprocess `tail`.
- Ordine di `allowed_roots` **non è semanticamente significativo**: il
  path è valido se cade in almeno un root, indipendentemente dalla
  posizione di questo nella lista. Sovrapposizioni (es. `/var/log` e
  `/var/log/devbox-bridge`) restano consistenti.
- Root inesistenti vengono **saltati silenziosamente**: smontare un
  mountpoint non rompe l'intera validazione.

#### Perché l'ordine whitelist → esistenza

Se `resolve_within_any` controllasse l'esistenza prima della whitelist,
un attaccante autenticato distinguerebbe "path fuori whitelist" da
"path inesistente" osservando il tipo di errore — info-leak debole ma
asimmetrico (può enumerare path applicativi che NON dovrebbe sapere
esistere). Con il check whitelist-first, un path fuori whitelist
solleva sempre `PathSecurityError` indipendentemente dall'esistenza
reale del file. L'attaccante può solo osservare l'esistenza di file
DENTRO la whitelist — superficie minima e attesa.

### list_systemd_services — asimmetria intenzionale rispetto a read_journalctl

A differenza di `read_journalctl` e `tail_log`, `list_systemd_services`
**non ha una whitelist hard di unit**. Ha solo un substring filter
opzionale (`name_filter`, default `system.systemd_filter_default =
"devbox-"`), che il client può svuotare passando `name_filter=""` per
ottenere l'enumerazione completa di tutte le service unit del sistema
(~150 entry su Ubuntu Server tipico).

Asimmetria difendibile:

- **`list_systemd_services` restituisce solo metadati pubblici**: nome
  unit, `load`/`active`/`sub` state, descrizione. Niente content.
  L'operatore con accesso shell ottiene gli stessi dati con
  `systemctl list-units`. Per il single-tenant attuale non aggiunge
  superficie di disclosure rispetto a quanto già accessibile.
- **`read_journalctl` legge i log applicativi**: questi possono contenere
  PII, secret loggati per errore, query DB, ecc. Per questo è whitelist
  hard.
- **`tail_log` legge file di log arbitrari**: stesso ragionamento. Whitelist
  hard sui root permessi.

Se un futuro use case (es. multi-tenant, audit shipping verso SIEM
esterno) richiedesse di nascondere i nomi unit, andrebbe aggiunto un
`systemd_unit_visible` whitelist analogo a `systemd_unit_whitelist` per
journal. Out of scope MVP.

### PathSecurityError vs PermissionError — distinguere il livello d'errore

Un client che riceve un errore dal bridge può vedere un wrapping
`ToolError` con messaggio. La distinzione tra:

- `PathSecurityError` → `event="path.rejected"`, `outcome="denied"`:
  il bridge ha rifiutato la richiesta a livello applicativo (whitelist,
  traversal, symlink escape).
- `PermissionError`/`OSError` (errno 13 EACCES) → `event="tool.<name>"`,
  `outcome="error"`: il bridge ha provato l'I/O e il kernel ha
  risposto EACCES (tipicamente perché il service user non può
  attraversare un parent path).

Sono **percorsi d'errore diversi ma proprietà di sicurezza
equivalente**: in entrambi i casi il dato non viene esfiltrato. EACCES
indica però un bug operativo (mancanza di traversal `--x` ACL su un
parent), non una vulnerabilità del bridge. Vedi `SETUP.md → install.sh`
per il fix least-privilege con `setfacl -m u:devbox-bridge:--x` sui
parent path dei progetti.

### Unit validation per journalctl

`read_journalctl(unit)` applica due gate:

1. `unit` deve matchare regex `^[A-Za-z0-9._@:-]{1,64}$` — defense-in-depth
   contro injection in argomenti CLI (anche se `subprocess.run` è
   `shell=False`). Lo stesso pattern vale per `name_filter` di
   `list_systemd_services`.
2. `unit` deve essere in `system.systemd_unit_whitelist`.

### Permessi di lettura del journal

L'utente che esegue il bridge deve avere accesso al journal per le unit
in `system.systemd_unit_whitelist`. **Default: gruppo `systemd-journal`**
(NON `adm`). Razionale: con la whitelist di default
(`["devbox-bridge.service"]`) l'unica unit accessibile è il servizio
stesso, quindi `systemd-journal` è sufficiente e segue least privilege.
`adm` aggiungerebbe accesso anche a `/var/log/syslog`,
`/var/log/auth.log`, ecc. che il bridge per design non tocca.

`deploy/install.sh` esegue `usermod -aG systemd-journal devbox-bridge`
e fail-fast se la membership non è applicata.

Se in futuro un operatore amplia `system.log_paths_whitelist` (es.
aggiunge `/var/log/syslog`), dovrà aggiungere `adm` manualmente —
decisione consapevole, non automatica.

Smoke test della membership effettiva:

```bash
sudo -u devbox-bridge journalctl -u devbox-bridge.service -n 5
```

Se ritorna entries → OK. Se ritorna "No journal files were found" o
"Hint: You are currently not seeing messages from other users" → la
membership non è applicata; verificare `id devbox-bridge` e ri-eseguire
`install.sh`.

### Modello PII / single-tenant

I tool sistema espongono info **non sensibili nel modello single-tenant
attuale**: hostname, kernel version, df totals, lista servizi systemd,
contenuto file di log whitelistati. Un eventuale refactoring multi-tenant
richiederebbe filtering aggiuntivo (hide-mounts per tenant,
namespace-scoped systemctl, log path partition). Out of scope per l'MVP,
documentato come commento in `tools/system.py`.

## Progetti two-key — EvoTrader e Robo-PAC ETF

Regola **prospettica**: oggi nessuno dei due progetti è abilitato in
`config.yaml.example` (entrambi commentati con warning). La policy
operativa "two-key" — `write_enabled` + `command_whitelist`
safe-by-construction — vive in `PM-MCP-PROJECT.md` sezione *"Cosa il
bridge NON farà mai"* e nei warning del file di config esempio.

In sintesi: anche se in futuro `write_enabled: true` venisse abilitato
su `evotrader` o `robo-pac-etf`, la `command_whitelist` non deve mai
contenere pattern che possano emettere ordini reali (entry-point live
verso Interactive Brokers o Trade Republic). Sono permessi solo
test/lint/backtest dry-run.

Razionale: un comando malizioso scivolato in conversazione (anche come
tool-use suggerito da una pagina web letta in claude.ai) non deve mai
poter muovere capitali. Per il dettaglio della policy e del razionale
"due chiavi" vedi `PM-MCP-PROJECT.md`.
