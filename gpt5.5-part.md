# GPT-5.5 part — step 7

Documento di dettaglio sugli interventi fatti da GPT-5.5 nello step 7.

## Obiettivo

Completare lo skeleton funzionante di `src/devbox_bridge/server.py`, cioe il punto
di composizione tra FastMCP, autenticazione, rate limit, audit log e i tool
filesystem gia implementati nello step 6.

## File modificati

- `src/devbox_bridge/server.py`
- `tests/test_server.py`
- `HANDOFF.md`
- `README.md`
- `docs/SETUP.md`
- `docs/SECURITY.md`
- `docs/TOOLS.md`
- `PM-MCP-PROJECT.md`
- `gpt5.5-part.md`

## `server.py`

Ho sostituito lo stub con un entrypoint FastMCP reale.

Componenti aggiunti:

- `create_mcp(config, audit=None)`: costruisce `FastMCP("devbox-bridge")` e
  registra i 6 tool filesystem gia disponibili.
- `create_http_app(config, audit=None)`: costruisce la Starlette app FastMCP su
  path `/mcp`, avvolta dal middleware di autenticazione.
- `main()`: carica `config.yaml` da `DEVBOX_BRIDGE_CONFIG` o da `config.yaml`,
  inizializza `AuditLogger`, `Authenticator`, FastMCP e avvia il transport HTTP.
- `BearerAuthMiddleware`: middleware ASGI che valida `Authorization: Bearer ...`,
  applica rate limit dopo auth success e traduce gli errori in HTTP.
- Helper per token, client IP, mapping audit e summary argomenti.

Comportamenti implementati:

- Token mancante o invalido: `401` con body generico `unauthorized`.
- Rate limit superato: `429` con header `Retry-After: 60`.
- `client_ip`: prima voce di `X-Forwarded-For`, fallback a `request.client.host`.
- IP non valido: log/audit con `client_ip="(invalid)"`, senza bloccare.
- Tool read auditati solo se `audit.audit_reads=true`, perche `AuditLogger`
  applica gia la policy.
- Tool write sempre auditati.
- `PathSecurityError`, `GlobSecurityError`, `WriteNotAllowedError` mappati su
  `event="path.rejected"` e `outcome="denied"`.
- Altre eccezioni tool mappate su `event="tool.<name>"` e `outcome="error"`.
- Success tool mappato su `event="tool.<name>"` e `outcome="success"`.
- Il contenuto passato a `write_file` viene riassunto in audit con
  `summarize_content`, non loggato in chiaro.

Nota tecnica: FastMCP rifiuta funzioni tool con `**kwargs` perche genera lo schema
MCP dalla signature Python. Per questo i sei tool sono registrati come funzioni
esplicite (`read_file(project, rel_path)`, ecc.) e usano un helper comune
`_call_with_audit()` solo internamente.

## Tool registrati

Implementati nello step 7 come tool MCP effettivamente esposti:

- `list_projects()`
- `read_file(project, rel_path)`
- `write_file(project, rel_path, content, create=False)`
- `apply_patch(project, rel_path, old, new)`
- `list_directory(project, rel_path=".")`
- `search_files(project, pattern, glob="*", max_matches=500)`

Restano pending per step futuri:

- Tool git in `tools/git.py`
- Tool execution in `tools/execution.py`
- Tool system in `tools/system.py`

## Test aggiunti

Ho aggiunto `tests/test_server.py` con 12 test mirati:

- parsing bearer token;
- split `host:port`;
- `create_http_app()` su `/mcp`;
- registrazione dei 6 tool filesystem;
- chiamata FastMCP diretta a `read_file`;
- audit success per `write_file`;
- audit denied per write su progetto read-only;
- middleware auth con token mancante;
- middleware auth con token valido;
- rate limit con `Retry-After: 60`;
- parsing del primo IP da `X-Forwarded-For`;
- marcatura IP invalido come `(invalid)`.

## Verifiche eseguite

Comandi eseguiti dopo le modifiche:

```bash
.venv/bin/pytest -q
.venv/bin/mypy src
.venv/bin/ruff check src/devbox_bridge/server.py tests/test_server.py
```

Risultati:

- `237 passed, 1 skipped`
- `mypy src`: nessun errore
- `ruff` sui file dello step 7: nessun errore

Nota: `ruff check src tests` sull'intero repository segnala ancora problemi
preesistenti in `src/devbox_bridge/tools/filesystem.py` e
`tests/test_tools_filesystem.py`. Non li ho modificati nello step 7 per non
allargare il perimetro.

## Scelte deliberate

- Ho usato il transport HTTP FastMCP su `/mcp`, coerente con la versione
  pinnata `fastmcp==3.2.4`.
- Ho lasciato l'auth come middleware ASGI invece che come auth provider OAuth
  FastMCP, perche il brief richiede bearer token locale semplice basato su hash
  SHA-256.
- Ho tenuto i tool filesystem puri: nessun audit dentro `tools/filesystem.py`.
  Il server aggiunge contesto auth/client IP e decide l'audit.
- Non ho implementato git/execution/system: sono step 8-10.
- Non ho fatto commit ne push.
