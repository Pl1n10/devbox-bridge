# SECURITY — Threat model

> Stato step 10: threat model e audit di tutti i componenti implementati
> sono documentati. Inclusi: backstop dei tool git (step 8), gating exec su
> `write_enabled` + deny list su comandi configurati (step 9), whitelist
> path/unit per i tool sistema con semantica fail-secure (step 10).

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

- User dedicato `devbox-bridge` (no sudo)
- systemd hardening: `ProtectSystem=strict`, `NoNewPrivileges`, capabilities drop
- Cloudflare Access davanti al tunnel come 2° fattore (consigliato)
- Audit log su file separato per ogni azione write/exec

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

### Eventi auditati

Sempre loggati:
  - `auth.failed`, `auth.rate_limited`
  - `command.rejected`, `path.rejected`
  - Tutti i tool write/exec: `tool.write_file`, `tool.apply_patch`,
    `tool.git_commit`, `tool.git_push`, `tool.git_create_branch`,
    `tool.run_command`, `tool.run_tests`, `tool.run_lint`, `tool.run_build`

Loggati solo se `audit.audit_reads: true` in config:
  - `tool.read_file`, `tool.list_projects`, `tool.list_directory`,
    `tool.search_files`, `tool.git_status`, `tool.git_diff`, `tool.git_log`,
    `tool.git_branch_current`, `tool.tail_log`,
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
allowed_roots)`:

- `path` deve essere **assoluto** (path relativi rifiutati con
  `PathSecurityError`).
- `path` deve **esistere** (`Path.resolve(strict=True)` propaga
  `FileNotFoundError`, distinto da "fuori whitelist").
- Tutti i symlink lungo il path candidato vengono **risolti prima del
  confronto**: un symlink dentro la whitelist che punta fuori (es.
  `/var/log/devbox-bridge/x → /etc/passwd`) viene rifiutato.
- Ordine di `allowed_roots` **non è semanticamente significativo**: il
  path è valido se cade in almeno un root, indipendentemente dalla
  posizione di questo nella lista. Sovrapposizioni (es. `/var/log` e
  `/var/log/devbox-bridge`) restano consistenti.
- Root inesistenti vengono **saltati silenziosamente**: smontare un
  mountpoint non rompe l'intera validazione.

### Unit validation per journalctl

`read_journalctl(unit)` applica due gate:

1. `unit` deve matchare regex `^[A-Za-z0-9._@:-]{1,64}$` — defense-in-depth
   contro injection in argomenti CLI (anche se `subprocess.run` è
   `shell=False`). Lo stesso pattern vale per `name_filter` di
   `list_systemd_services`.
2. `unit` deve essere in `system.systemd_unit_whitelist`.

### Permessi di lettura del journal

L'utente che esegue il bridge deve avere accesso al journal system-wide
per `read_journalctl` su unit di sistema. Su Ubuntu, l'appartenenza ai
gruppi **`adm`** o **`systemd-journal`** è sufficiente. Verifica:

```bash
journalctl -u systemd-journald.service -n 5
```

Se ritorna entries → OK. Se ritorna "No journal files were found" o "Hint:
You are currently not seeing messages from other users" → aggiungere
l'utente a `adm` (`sudo usermod -aG adm <user>` + nuovo login). Lo step 11
(`install.sh`) include questo check come fail-fast pre-deploy.

### Modello PII / single-tenant

I tool sistema espongono info **non sensibili nel modello single-tenant
attuale**: hostname, kernel version, df totals, lista servizi systemd,
contenuto file di log whitelistati. Un eventuale refactoring multi-tenant
richiederebbe filtering aggiuntivo (hide-mounts per tenant,
namespace-scoped systemctl, log path partition). Out of scope per l'MVP,
documentato come commento in `tools/system.py`.

## Progetti two-key — EvoTrader e Robo-PAC ETF

Questi due progetti hanno guardrail finanziari nel global context e richiedono una
regola di sicurezza aggiuntiva, **anche oltre quanto enforced dal codice**:

> Anche se in futuro abilitassi `write_enabled: true` su `evotrader` o `robo-pac-etf`,
> NON si abilita mai un `command_whitelist` con pattern che possano emettere ordini
> reali. In particolare:
> - **Vietato:** `^python -m robopac\.execute.*$`, `^python -m evotrader\.live.*$`,
>   qualsiasi entry-point CLI che parli con Interactive Brokers o Trade Republic in
>   modalità live.
> - **Permesso:** `^pytest( .*)?$`, `^ruff( .*)?$`, eventuali backtest in dry-run.

Razionale: un comando malizioso scivolato in conversazione (anche solo come tool-use
suggerito da una pagina web letta in claude.ai) non deve mai poter muovere capitali.
Il principio è "due chiavi" — `write_enabled` da solo non basta, serve anche una
whitelist comandi dimostrabilmente safe-by-construction.
