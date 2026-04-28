"""FastMCP entrypoint.

TODO (step 7): istanziare FastMCP, registrare i tool da `tools/*`,
applicare auth + rate limit, esporre HTTP/SSE su config.server.bind.

  mcp = FastMCP("devbox-bridge")
  @mcp.tool() async def list_projects(): ...
  ...
  if __name__ == "__main__": main()

Note di integrazione auth (concordate con review step 3):
  - AuthFailed → 401 Unauthorized con body generico ("unauthorized"); NIENTE
    `reason` esposto al client (resta solo nei log server-side).
  - RateLimitExceeded → 429 Too Many Requests con header `Retry-After: 60`.
  - client_ip:
      1) prendere `X-Forwarded-For` se presente (Cloudflare Tunnel passa
         l'IP originale lì); usare il primo elemento della catena
         "ip1, ip2, ip3" → ip1.
      2) altrimenti `request.client.host`.
      3) sanitizzazione: validare l'IP con `ipaddress.ip_address()`,
         se fallisce loggare `client_ip="(invalid)"` e proseguire.
"""


def main() -> None:
    raise NotImplementedError("server.py non ancora implementato — vedi step 7 del brief")


if __name__ == "__main__":
    main()
