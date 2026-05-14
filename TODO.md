# TODO.md — Issue aperte non ancora risolte

> Diverso da `FAILURES.md` (che documenta scelte deliberate di NON fare qualcosa).
> Qui finiscono i problemi noti che vogliamo affrontare, con priorità e contesto.
> Quando un'issue viene chiusa, sposta la voce in `HANDOFF.md` sotto la milestone giusta.

## Template

```
### YYYY-MM-DD — <breve titolo>  [priorità: low|med|high]
**Sintomo:** ...
**Cause probabili:** ...
**Opzioni di fix considerate:** ...
**Prossima azione:** ...
```

---

## Voci aperte

### 2026-05-13 — Binari del venv progetto non risolvono dal PATH del bridge  [priorità: med]

**Sintomo:** chiamando `run_command` con un comando whitelistato come `ruff --version` (whitelist `^ruff( .*)?$`), il check di whitelist passa ma l'esecuzione fallisce con `executable 'ruff' non trovato nel PATH`. Stessa cosa attesa per `pytest`, `mypy`, e qualunque binario installato in `<project>/.venv/bin/`.

**Cause probabili:** il processo `devbox-bridge` gira con `ProtectSystem=strict` e PATH minimale ereditato da systemd (verosimilmente `/usr/local/bin:/usr/bin:/bin`). I binari del progetto vivono in `/home/hypn0/projects/<proj>/.venv/bin/`, che non è nel PATH. La whitelist regex matcha solo la stringa del comando, non risolve il path del binario.

**Opzioni di fix considerate:**

1. **Drop-in systemd per-progetto con PATH esteso.** Aggiungere al drop-in `projects.conf` un `Environment=PATH=...` che include il `.venv/bin/` di ogni progetto registrato. Ugly: il PATH cresce linearmente con N progetti, e si rompe se un progetto non ha `.venv/`.

2. **Whitelist con path assoluti.** Riscrivere le regex come `^/home/hypn0/projects/devbox-bridge/\.venv/bin/(pytest|ruff|mypy)( .*)?$`. Chiaro e auditabile, ma rigido: rinominare il venv o spostare il progetto rompe tutto. Inoltre il modello mentale "ruff" diventa "path lungo", scomodo da scrivere a mano.

3. **Risoluzione comando lato bridge.** Modificare l'engine di `run_command` perché, prima di eseguire, cerchi il primo eseguibile fra: `<project_path>/.venv/bin/<argv0>`, `<project_path>/node_modules/.bin/<argv0>`, poi PATH di sistema. La whitelist matcha sempre l'`argv0` originale ("ruff"), la risoluzione è trasparente. Più lavoro lato codice, ma è il comportamento corretto e scala a Node/Go/Rust progetti.

**Prossima azione:** opzione 3 è quella giusta a tendere, ma è lavoro Python non banale. Per sbloccare l'uso a breve, valutare opzione 1 come patch temporanea (richiede solo modifica di `deploy/install.sh` nella sezione che genera `projects.conf`). Decidere quando si riprende il lavoro sul bridge.

**Discovered durante:** prima sessione di test MCP con `write_enabled=true` sul progetto `devbox-bridge` stesso (2026-05-13). Riprodotto con `ruff --version`.
