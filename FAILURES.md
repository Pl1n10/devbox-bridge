# FAILURES.md — Approcci scartati e perché

> Per Claude Code futuro: leggimi prima di riproporre soluzioni che potrebbero
> essere già state valutate e scartate.

## Template

```
### YYYY-MM-DD — <breve titolo>
**Approccio scartato:** ...
**Perché non funziona / non è andato bene:** ...
**Alternativa adottata:** ...
```

## Voci

### 2026-04-29 — coverage step 6 (tools/filesystem.py): 5 cluster di righe lasciati scoperti volontariamente

**Approccio scartato:** portare il coverage di `tools/filesystem.py` oltre il 90% testando tutti i rami difensivi rimasti.

**Perché non funziona / non è andato bene:** richiede ingegneria sproporzionata per confidenza marginale. Le 19 righe scoperte si dividono in 5 cluster, tutti con costo-test alto e rendimento-confidenza basso:

1. **Ramo `<external>` post-`resolve_within`** (linee 128-129, 508-510). Defense-in-depth: il fallback `relative_to` fallisce solo se il path passa già `resolve_within` ma diventa esterno tra il check e l'uso (impossibile in pratica perché entrambi avvengono in stack frame consecutivi). Testarlo richiederebbe monkey-patch di `relative_to`, che dimostra solo "il monkey-patch funziona".
2. **Race FS su `child.stat()` / symlink loop** (353-354, 380-381). `try/except OSError` cattura "file rimosso tra `iterdir()` e `stat()`". Testabile solo orchestrando race condition con thread → ingegneria sproporzionata.
3. **`subprocess.TimeoutExpired` di rg** (454-455). Testabile solo con `time.sleep(31)` in un fixture (lento, fragile) o monkey-patch di `subprocess.run` (testa il monkey-patch, non il codice).
4. **rg exit code ≠ {0, 1}** (461). Richiederebbe corromper il binario `rg` o mock di `subprocess.run`.
5. **stdout rg corrotto** (469, 472-473, 503): righe vuote / non-JSON / path-text vuoto. Robustness su output ipotetico mai osservato in 14 anni di rg.

Inoltre lasciate scoperte ma di natura analoga (OSError edge che NON sono input utente diretti, irraggiungibili dai 38 test correnti):
- 334, 336: `list_directory` su rel_path inesistente / non-dir. Coverabili se servisse, ma simmetrici ai test `read_file_on_directory` già presenti.
- 363: branch `else: type="other"` per socket/fifo/devnode dentro un progetto (esotico).

**Alternativa adottata:** copertura al **90%** (target del brief) con i 38 test che coprono tutti i percorsi di security (path traversal, write enforcement, binary refuse, encoding strict, glob escape, ripgrep mancante) e tutti gli input utente legittimi (file inesistente, directory passata come file, max_matches=0, glob vuoto/home-relative). Le 19 righe scoperte sono error-handling difensivo, non gap funzionali.

Se in futuro arriva un bug dal campo che riguarda una di queste linee, **allora** vale la pena scrivere il test (regressione mirata). Senza un caso reale, no.

### 2026-05-04 — step 11: scartate due alternative all'approccio "ACL chirurgiche per progetto"

Per dare all'utente di servizio `devbox-bridge` accesso ai progetti in `/home/hypn0/projects/*` ho valutato tre opzioni. La (1) ACL chirurgiche è quella adottata in `deploy/install.sh`. Le altre due sono state scartate esplicitamente — annoto qui il perché così non vengano riproposte tra mesi come "scorciatoia che sembra innocua".

**Opzione (2) — aggiungere `devbox-bridge` al gruppo `hypn0`.**

**Approccio scartato:** `usermod -aG hypn0 devbox-bridge` + `chmod g+rX` su `/home/hypn0/projects`. Una sola riga, "tanto i progetti sono già lì".

**Perché non va bene:** rompe il principio di least privilege. Membership in `hypn0` dà accesso *all'intera home* di hypn0, non solo ai progetti opt-in del config: `~/.ssh/`, `~/.config/`, eventuali `.env` di progetti **non in `config.yaml`**, file di sessione, ecc. È esattamente il tipo di "scorciatoia che sembra innocua" che il threat model del bridge è nato per evitare. Una volta concessa la membership non c'è più separazione fra progetti opt-in e tutto il resto della home.

**Alternativa adottata:** ACL `setfacl -R -m u:devbox-bridge:r-X` (o `rwX` con default ACL se `write_enabled: true`) per **ogni** path elencato in `config.yaml`, applicate dall'installer. Il bridge non ha alcun accesso al resto di `/home/hypn0/`.

---

**Opzione (3) — far girare il servizio come `hypn0`.**

**Approccio scartato:** `User=hypn0` nella unit, niente service user dedicato. "Tanto è la stessa devbox, le ACL sono inutili".

**Perché non va bene:** viola il brief (che chiede esplicitamente "non root, non hypn0") ma soprattutto **annulla mezzo systemd hardening**:

- `ProtectHome=read-only` diventa irrilevante se l'utente del servizio è il proprietario di `/home/hypn0/` — il read-only protegge dai tentativi di scrivere fuori contesto, ma se sei tu l'owner stai modificando legittimamente la tua home.
- Si perde la separazione che permette di dire *"il bridge non può toccare nulla fuori dai progetti opt-in"* con una **garanzia kernel-level**, non solo applicativa. Un eventuale baco che bypassa il check `write_enabled` finisce a scrivere file in `~/.bashrc`, `~/.gitconfig` o ovunque.
- Cancella `MemoryDenyWriteExecute`, `RestrictSUIDSGID` e gli altri strict come strumenti di confinamento utili: tanto il processo gira come l'utente "vero" della macchina.

**Alternativa adottata:** utente di servizio dedicato `devbox-bridge` (system, no-login) + ACL chirurgiche + drop-in `ReadWritePaths=` generato dall'installer da `config.yaml`. Difesa applicativa (check `write_enabled` nei tool) e difesa kernel (ACL + namespace systemd) sono **in serie**, non ridondanti — un baco a un layer non basta a bucare l'altro.
