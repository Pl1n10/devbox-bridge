FROM python:3.12-slim

# Runtime deps:
#   - git: tool MCP git_*
#   - ripgrep: search_files (tools/filesystem.py)
RUN apt-get update && apt-get install -y --no-install-recommends \
        git \
        ripgrep \
    && rm -rf /var/lib/apt/lists/*

# Service user con UID/GID fissi 9876 — utile per allineare permessi sui
# bind mount host-side (/var/log/devbox-bridge in particolare).
RUN groupadd -r -g 9876 devbox-bridge \
 && useradd -r -u 9876 -g 9876 -s /usr/sbin/nologin devbox-bridge

WORKDIR /app

# Layer cache: requirements.lock prima del codice. Build da lockfile
# transitivo per riproducibilità (vedi CLAUDE.md "Dependency management").
COPY requirements.lock pyproject.toml README.md ./
RUN pip install --no-cache-dir -r requirements.lock

# Codice + install editable senza deps (già installate da requirements.lock).
COPY src ./src
RUN pip install --no-cache-dir -e . --no-deps

USER devbox-bridge
EXPOSE 8765
ENV DEVBOX_BRIDGE_CONFIG=/etc/devbox-bridge/config.yaml \
    PYTHONUNBUFFERED=1

ENTRYPOINT ["devbox-bridge"]
