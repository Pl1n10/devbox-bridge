# Brief per Claude Code: MCP Server "devbox-bridge"

## Contesto

Sto creando un MCP server custom che girerà su questa stessa VM e sarà esposto via Cloudflare Tunnel come custom connector su claude.ai. Lo scopo è permettere alle conversazioni claude.ai di interagire con questa devbox (filesystem dei miei progetti, git, esecuzione test, build) in modo controllato.

**Per il contesto sui progetti**, leggi `~/.claude/CLAUDE.md` (che hai già caricato automaticamente come global context) — è la fonte di verità sui 14 progetti che dovrai gestire. In alternativa lo stesso contenuto si trova in `~/CONTEXT.md`.

**Devbox setup:**
- User: `hypn0`
- Home: `/home/hypn0`
- Progetti: `/home/hypn0/projects/*` (verifica i path effettivi quando popoli la config)
- Dominio target del tunnel: `mcpdev.robertonovara.me`

## Obiettivo

Crea un repository `devbox-bridge` in `/home/hypn0/projects/devbox-bridge` con:

1. Un MCP server in Python (FastMCP) che espone tool sicuri sulla devbox
2. Tutto il setup di deploy: `systemd` unit, `docker-compose.yml` come alternativa, config Cloudflare Tunnel
3. Documentazione completa per registrarlo come custom connector su claude.ai
4. Test (pytest) per la logica di sicurezza

## Stack richiesto

- **Python 3.11+**
- **FastMCP** (`pip install fastmcp`) — framework ufficiale Anthropic per MCP server
- **Transport:** HTTP/SSE (NON stdio — deve essere remote)
- **Auth:** bearer token in header `Authorization`, validato dal server. Cloudflare Access farà da secondo layer davanti (configurato dopo, manualmente da me).
- **Logging:** structured JSON su stdout (così systemd/journald lo cattura), più file rotante in `/var/log/devbox-bridge/`

## Tool da esporre

Implementa questi tool MCP, in questo ordine di priorità:

### Filesystem (read-only di default, write con flag esplicito)

- `list_projects()` → ritorna lista progetti dalla config YAML
- `read_file(path: str)` → legge un file. Path validato contro whitelist progetti.
- `list_directory(path: str)` → ls strutturato (nome, tipo, size, mtime). Skip `node_modules`, `.git`, `__pycache__`, `.venv`, `dist`, `build`.
- `search_files(project: str, pattern: str, glob: str = "*")` → ripgrep wrapper, output JSON
- `write_file(path: str, content: str, create: bool = False)` → richiede progetto in whitelist write-enabled
- `apply_patch(path: str, old: str, new: str)` → str-replace style, fail se `old` non univoco

### Git

- `git_status(project: str)` → status porcelain parsato
- `git_diff(project: str, staged: bool = False, path: str | None = None)` → diff testuale
- `git_log(project: str, limit: int = 20)` → log strutturato
- `git_branch_current(project: str)`
- `git_create_branch(project: str, name: str)` — write
- `git_commit(project: str, message: str, paths: list[str])` — write, mai `git commit -a`
- `git_push(project: str, remote: str = "origin")` — write, richiede flag `allow_push: true` nel config del progetto

NON implementare: `git_reset --hard`, `git_push --force`, `git_clean`, eliminazione di branch.

### Esecuzione

- `run_tests(project: str)` → esegue il comando di test definito in config (es. `pytest`, `go test ./...`, `npm test`)
- `run_lint(project: str)` → idem per lint (`ruff`, `golangci-lint`, `eslint`)
- `run_build(project: str)` → build command da config
- `run_command(project: str, command: str, timeout: int = 60)` → comando arbitrario MA solo se il comando matcha la whitelist regex del progetto. Default deny.

Tutti i comandi:
- Eseguiti con `subprocess.run`, mai `shell=True`
- Timeout obbligatorio (max 600s)
- Output troncato a 100KB con avviso
- `cwd` forzato alla root del progetto
- Env sanitizzato: rimuovi `AWS_*`, `*_TOKEN`, `*_SECRET`, `*_KEY` dall'env passato (tranne quelli esplicitamente whitelisted nel config del progetto)

### Sistema (read-only)

- `get_system_info()` → uptime, load, df, free
- `list_systemd_services(filter: str = "devbox-")` → status dei servizi che mi interessano
- `tail_log(path: str, lines: int = 100)` → tail di log path in whitelist (`/var/log/devbox-bridge/*`, `journalctl -u <servizio whitelisted>`)

## Configurazione

File `config.yaml` nella root del repo:

```yaml
server:
  bind: "127.0.0.1:8765"
  log_level: "INFO"
  log_dir: "/var/log/devbox-bridge"

auth:
  # bearer token sha256 hash; il token plain sta in /etc/devbox-bridge/token (chmod 600)
  token_hash_file: "/etc/devbox-bridge/token.sha256"

projects:
  sidebiz-agent:
    path: "/home/hypn0/projects/sidebiz-agent"
    write_enabled: false
    allow_push: false
    test_command: "pytest -x --tb=short"
    lint_command: "ruff check ."
    build_command: null
    command_whitelist:
      - "^pytest( .*)?$"
      - "^ruff( .*)?$"
      - "^alembic upgrade head$"
    env_passthrough:
      - "DATABASE_URL_TEST"

  nbu-control-room:
    path: "/home/hypn0/projects/control-room"
    write_enabled: false
    allow_push: false
    test_command: "npm test -- --run"
    lint_command: "npm run lint"
    build_command: "npm run build"
    command_whitelist:
      - "^npm (test|run lint|run build|ci)( .*)?$"
    env_passthrough: []

  # ... altri progetti
```

Genera la config iniziale con tutti i 14 progetti dal `~/.claude/CLAUDE.md`, con `write_enabled: false` di default. Li abiliterò io a mano dopo. Se il path effettivo di un progetto su `/home/hypn0/projects/` non lo trovi (es. la directory non esiste ancora), lascialo come placeholder commentato — non inventare path.

## Sicurezza — non negoziabili

1. **Path traversal:** ogni path va risolto con `Path.resolve()` e validato che sia dentro `projects[<name>].path`. Test esplicito per `..`, symlink esterni, path assoluti maliziosi.
2. **Comando shell injection:** mai `shell=True`. Comandi sempre in lista. Whitelist regex matchata sull'intero comando, non substring.
3. **Token auth:** verificato a tempo costante (`hmac.compare_digest`).
4. **Rate limit:** max 60 chiamate/minuto per token. Eccesso → 429.
5. **Audit log:** ogni chiamata a tool che modifica stato (`write_file`, `git_*` write, `run_*`) loggata su file separato `audit.log` con: timestamp, tool, args (sanitized), exit code, durata.
6. **Comandi distruttivi bloccati hardcoded** anche se in whitelist: regex deny list per `rm -rf`, `dd if=`, `mkfs`, `> /dev/`, `:(){ :|:& };:`, `curl .* | (sh|bash)`, `wget .* | (sh|bash)`.

## Deploy

Crea questi file nel repo:

### `deploy/devbox-bridge.service`
Systemd unit. User dedicato `devbox-bridge` (NON root, NON `hypn0`). Restart on failure. Hardening (`ProtectSystem=strict`, `ReadWritePaths=` solo dove serve, `NoNewPrivileges`, ecc.).

### `deploy/docker-compose.yml`
Alternativa containerizzata. Mount dei progetti read-only di default, read-write solo se `write_enabled`.

### `deploy/cloudflared-config.yml`
Snippet per il tunnel:
```yaml
ingress:
  - hostname: mcpdev.robertonovara.me
    service: http://127.0.0.1:8765
  - service: http_status:404
```
(uso già cloudflared come servizio, mi basta aggiungere l'ingress)

### `deploy/install.sh`
Script idempotente che:
- Crea user `devbox-bridge`
- Crea dir `/etc/devbox-bridge`, `/var/log/devbox-bridge`
- Genera token random se non esiste, salva sha256 in `token.sha256`, mostra il token plain UNA VOLTA in stdout
- Installa il systemd unit
- NON fa enable/start automatico — solo dice all'utente cosa fare

## Test

`pytest` in `tests/`:

- `test_path_safety.py` — tutti i casi di path traversal devono fallire
- `test_command_whitelist.py` — regex matching, deny list precedence
- `test_auth.py` — token validation, rate limit
- `test_tools_filesystem.py` — read/write/list su tmp dir
- `test_tools_git.py` — usa repo git temporaneo
- `test_audit_log.py` — verifica che azioni write siano loggate

Coverage target: 90% sulla logica di sicurezza (`security/`, `auth/`).

## Documentazione

### `README.md`
- Cosa fa
- Quick start (locale, in dev)
- Struttura del progetto
- Link al setup deploy

### `docs/SETUP.md`
Step-by-step per:
1. Installare le dipendenze
2. Configurare i progetti in `config.yaml`
3. Lanciare `install.sh`
4. Configurare l'ingress Cloudflare Tunnel su `mcpdev.robertonovara.me`
5. (opzionale) Configurare Cloudflare Access davanti al tunnel
6. Registrare il connector su claude.ai (URL del tunnel + token come bearer)
7. Test della connessione

### `docs/SECURITY.md`
Threat model esplicito: cosa l'MCP server NON protegge (es. se passo `write_enabled: true` su un progetto, Claude può modificarlo; non c'è un secondo livello di approvazione per file). Lista delle mitigazioni.

### `docs/TOOLS.md`
Reference di tutti i tool MCP esposti, con esempi di chiamata e output.

### `CLAUDE.md` (locale al repo, NON quello globale `~/.claude/CLAUDE.md`)
Per Claude Code futuro che lavorerà su QUESTO repo: convenzioni del progetto, come aggiungere un nuovo tool, dove sono i test, come si fa una release.

### `FAILURES.md`
Inizialmente vuoto ma con la struttura pronta. Ci scriveremo dentro gli approcci scartati man mano.

## Struttura repo proposta

```
devbox-bridge/
├── README.md
├── CLAUDE.md
├── FAILURES.md
├── pyproject.toml
├── config.yaml.example
├── src/
│   └── devbox_bridge/
│       ├── __init__.py
│       ├── server.py           # FastMCP app
│       ├── config.py           # pydantic settings
│       ├── auth.py             # bearer + rate limit
│       ├── audit.py            # audit logger
│       ├── security/
│       │   ├── paths.py        # path traversal guard
│       │   ├── commands.py     # whitelist + deny list
│       │   └── env.py          # env sanitizer
│       └── tools/
│           ├── filesystem.py
│           ├── git.py
│           ├── execution.py
│           └── system.py
├── tests/
├── deploy/
│   ├── devbox-bridge.service
│   ├── docker-compose.yml
│   ├── Dockerfile
│   ├── cloudflared-config.yml
│   └── install.sh
└── docs/
    ├── SETUP.md
    ├── SECURITY.md
    └── TOOLS.md
```

## Workflow di lavoro che ti chiedo

1. Crea prima la struttura completa di file vuoti/scheletro e mostrami l'albero
2. Implementa nell'ordine: `config.py` → `auth.py` → `security/*` → `tools/filesystem.py` → `server.py` (skeleton funzionante che possa partire) → `tools/git.py` → `tools/execution.py` → `tools/system.py`
3. Test ad ogni step (red-green)
4. Deploy file alla fine
5. Documentazione alla fine

**Importante:** dopo ogni step di implementazione, fermati, mostrami il diff e fai partire i test. Non procedere se i test falliscono.

**Non fare:**
- Modifiche sui miei progetti `/home/hypn0/projects/*` esistenti (solo lettura per popolare la config iniziale; l'unico progetto che crei sei `devbox-bridge` stesso)
- `git push` su qualunque cosa
- `systemctl enable/start` automatici
- Aprire porte sul firewall
- Modificare `~/.claude/CLAUDE.md` o `~/CONTEXT.md` (sono il global context, fuori scope per questo task)

## Quando hai finito

Dammi un riepilogo con:
- Cosa è stato fatto
- Cosa devo fare manualmente io (lista numerata)
- Il token plain generato (UNA VOLTA, poi sparisce)
- L'URL su cui registrare il connector: `https://mcpdev.robertonovara.me`

Procedi.
