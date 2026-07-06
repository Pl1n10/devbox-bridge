# DECISIONS — devbox-bridge

Decisioni di design non ovvie, numerate D-NNN. Le decisioni chiuse non si
rilitigano senza fatti nuovi. Per gli step 1-12 la fonte è
`docs/devbox-bridge-brief.md` + `docs/SECURITY.md`; questo file parte dallo
step 13.

## D-013 — Modulo notes: vault fuori da `projects:`, config via env

**Contesto.** Step 13 espone il vault Mnemosyne (`~/notes`, repo git con
origin sul Gitea della VM `mnemosyne`) come 6 tool MCP. Deriva da ADR-008
(vault esposto via devbox-bridge, non servizio nuovo) e ADR-009 (write
whitelist `llm/` + `inbox/`, pull-prima-di-scrivere, mai force-push,
nessuna delete) del repo mnemosyne — vedi `mnemosyne/DECISIONS.md`.

**Decisione.**

1. Il vault NON è un project in `config.yaml`: la sua policy (write
   whitelist per sottodirectory, pull-before-write, commit automatico) non
   coincide con `ProjectConfig` (`write_enabled` binario, commit espliciti
   dell'LLM, push gated da `allow_push`). Config separata `NotesConfig`
   letta da env (`NOTES_ROOT`, `NOTES_WRITE_DIRS`, `NOTES_MAX_READ_BYTES`),
   iniettabile nei test via `create_mcp(..., notes_config=...)`.
2. Riuso della security model esistente, non reimplementazione:
   `resolve_within` (containment), `sanitize_env` (+`GIT_TERMINAL_PROMPT=0`,
   `GIT_OPTIONAL_LOCKS=0`), eccezioni `WriteNotAllowedError` /
   `FileTooLargeError`, parser `_parse_porcelain_v1` di `tools/git.py`.
3. `notes_write` è commit+push atomico per file (i `notes_sync_commit` /
   `notes_sync_push` separati del design di maggio sono stati fusi — se
   emerge un caso d'uso reale per commit batch, nuovo ADR).
4. Accesso in produzione via `deploy/setup-notes-access.sh`, separato da
   `install.sh`: ACL rwX + default sul vault per il service user (e
   default ACL per hypn0, così il cron pull continua a gestire i file
   creati dal bridge), deploy key dedicata scoped al repo `notes`
   (root:devbox-bridge 0640 — NON la chiave di hypn0), known_hosts
   pinnato, drop-in systemd `notes.conf` (env + `ReadWritePaths`) distinto
   da `projects.conf` che `install.sh` rigenera da zero.
5. Identity dei commit MCP e `core.sshCommand` vivono in
   `/etc/devbox-bridge/notes_gitconfig`, collegato con
   `includeIf gitdir:<vault>/` nel gitconfig globale del SOLO service
   user. Repo-local avrebbe rotto il cron pull di hypn0 (chiave non
   leggibile); globale senza `includeIf` avrebbe rotto i push dei progetti
   verso GitHub (known_hosts pinnato solo su Gitea).

**Conseguenze.** Il vault ha due writer git: il bridge (commit+push per
nota) e Roberto da PC. Il cron su devbox resta pull-only (unico writer
automatico del working tree condiviso, invariante di mnemosyne
HANDOFF.md). I conflitti si manifestano come `NotesSyncError` sul write:
il bridge non risolve mai conflitti da solo.
