"""Tool MCP — sistema (read-only).

TODO (step 10):
  - get_system_info() -> {uptime, load1/5/15, df: list, free_mem}
  - list_systemd_services(filter: str = "devbox-") -> list[ServiceInfo]
      usa `systemctl list-units --type=service --no-pager`
  - tail_log(path: str, lines: int = 100) -> str
      whitelist:
        - /var/log/devbox-bridge/*.log
        - journalctl -u <servizio whitelisted>  (sintassi virtual: 'journalctl:<unit>')
"""

# placeholder — implementazione nello step 10
