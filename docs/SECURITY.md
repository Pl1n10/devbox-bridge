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
