"""FastMCP entrypoint.

TODO (step 7): istanziare FastMCP, registrare i tool da `tools/*`,
applicare auth + rate limit, esporre HTTP/SSE su config.server.bind.

  mcp = FastMCP("devbox-bridge")
  @mcp.tool() async def list_projects(): ...
  ...
  if __name__ == "__main__": main()
"""


def main() -> None:
    raise NotImplementedError("server.py non ancora implementato — vedi step 7 del brief")


if __name__ == "__main__":
    main()
