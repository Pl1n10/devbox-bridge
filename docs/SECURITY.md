# SECURITY — Threat model

> **Skeleton — da completare nello step 12.**

## Cosa devbox-bridge protegge

- Path traversal fuori dai progetti whitelisted
- Shell injection (no `shell=True`, whitelist regex con fullmatch, deny list hardcoded)
- Token brute-force (compare_digest + rate limit 60/min)
- Leak di secret via env (sanitizer rimuove `AWS_*`, `*_TOKEN`, `*_SECRET`, `*_KEY`)
- Comandi distruttivi noti (deny list hardcoded: `rm -rf`, `dd if=`, fork bomb, curl|sh, ...)

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
