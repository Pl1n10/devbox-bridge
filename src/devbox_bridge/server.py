"""FastMCP entrypoint."""

from __future__ import annotations

import ipaddress
import os
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any, cast

from fastmcp import FastMCP
from fastmcp.server.dependencies import get_http_request
from starlette.middleware import Middleware as ASGIMiddleware
from starlette.requests import Request
from starlette.responses import PlainTextResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from devbox_bridge.audit import AuditLogger, summarize_command_output, summarize_content
from devbox_bridge.auth import Authenticator, AuthFailed, RateLimitExceeded, token_log_id
from devbox_bridge.config import AppConfig, load_config
from devbox_bridge.security.commands import CommandRejectedError
from devbox_bridge.security.paths import PathSecurityError
from devbox_bridge.tools import execution, filesystem, system
from devbox_bridge.tools import git as git_tools
from devbox_bridge.tools.execution import DEFAULT_RUN_COMMAND_TIMEOUT_SECONDS
from devbox_bridge.tools.filesystem import GlobSecurityError, WriteNotAllowedError
from devbox_bridge.tools.git import PushNotAllowedError
from devbox_bridge.tools.system import (
    DEFAULT_LOG_LINES,
    JournalctlUnitNotAllowedError,
    LogPathNotAllowedError,
)

CONFIG_ENV_VAR = "DEVBOX_BRIDGE_CONFIG"
DEFAULT_CONFIG_PATH = "config.yaml"
MCP_HTTP_PATH = "/mcp"
RETRY_AFTER_SECONDS = "60"

# Tool exec — usati per popolare outcome_detail e per la sintesi audit di
# stdout/stderr. Tenuto qui (non in tools/execution.py) perché è policy server.
EXEC_TOOL_NAMES: frozenset[str] = frozenset(
    {"run_command", "run_tests", "run_lint", "run_build"}
)

# Truncate del campo `command` in args_summary audit. Protezione log poisoning:
# `run_command(... command="echo " + "A"*100000)` non deve generare 100KB di "A"
# in ogni linea audit. Sopra a questa soglia: `cmd[:N] + "...[truncated]"`.
COMMAND_AUDIT_TRUNCATE_CHARS: int = 500


def _extract_bearer_token(authorization: str | None) -> str | None:
    if not authorization:
        return None
    scheme, sep, token = authorization.strip().partition(" ")
    if sep != " " or scheme.lower() != "bearer" or not token.strip():
        return None
    return token.strip()


def _client_ip_from_request(request: Request) -> str | None:
    raw = request.headers.get("x-forwarded-for")
    if raw:
        raw = raw.split(",", 1)[0].strip()
    elif request.client is not None:
        raw = request.client.host

    if not raw:
        return None

    try:
        ipaddress.ip_address(raw)
    except ValueError:
        return "(invalid)"
    return raw


def _request_context() -> tuple[str | None, str | None]:
    try:
        request = get_http_request()
    except RuntimeError:
        return None, None
    token = _extract_bearer_token(request.headers.get("authorization"))
    return token_log_id(token), _client_ip_from_request(request)


class BearerAuthMiddleware:
    """ASGI middleware: bearer auth + per-token rate limit for HTTP transports."""

    def __init__(self, app: ASGIApp, authenticator: Authenticator, audit: AuditLogger) -> None:
        self.app = app
        self.authenticator = authenticator
        self.audit = audit

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request = Request(scope, receive)
        token = _extract_bearer_token(request.headers.get("authorization"))
        client_ip = _client_ip_from_request(request)

        try:
            self.authenticator.check(token, client_ip=client_ip)
        except AuthFailed:
            self.audit.log(
                "auth.failed",
                "denied",
                token_id=token_log_id(token),
                client_ip=client_ip,
                error_class="AuthFailed",
                error_message="unauthorized",
            )
            response = PlainTextResponse("unauthorized", status_code=401)
            await response(scope, receive, send)
            return
        except RateLimitExceeded:
            self.audit.log(
                "auth.rate_limited",
                "denied",
                token_id=token_log_id(token),
                client_ip=client_ip,
                error_class="RateLimitExceeded",
                error_message="rate limit exceeded",
            )
            response = PlainTextResponse(
                "too many requests",
                status_code=429,
                headers={"Retry-After": RETRY_AFTER_SECONDS},
            )
            await response(scope, receive, send)
            return

        await self.app(scope, receive, send)


def _event_for_tool(tool_name: str, exc: BaseException | None) -> str:
    if isinstance(
        exc,
        (
            PathSecurityError,
            GlobSecurityError,
            WriteNotAllowedError,
            LogPathNotAllowedError,
        ),
    ):
        return "path.rejected"
    if isinstance(exc, CommandRejectedError):
        return "command.rejected"
    return f"tool.{tool_name}"


def _outcome_for_exception(exc: BaseException) -> str:
    if isinstance(
        exc,
        (
            PathSecurityError,
            GlobSecurityError,
            WriteNotAllowedError,
            PushNotAllowedError,
            CommandRejectedError,
            LogPathNotAllowedError,
            JournalctlUnitNotAllowedError,
        ),
    ):
        return "denied"
    return "error"


def _outcome_detail_from_result(tool_name: str, result: Any) -> str | None:
    """Granularità sub-outcome per i tool exec (subprocess è stato eseguito).

    Valori: "completed" | "nonzero_exit" | "timed_out". None per gli altri tool.
    Non promuove a outcome="error" — il bridge ha eseguito il subprocess
    correttamente, il dettaglio descrive cosa è successo nel processo figlio.
    """
    if tool_name not in EXEC_TOOL_NAMES:
        return None
    if not isinstance(result, dict):
        return None
    if result.get("timed_out"):
        return "timed_out"
    if result.get("exit_code") != 0:
        return "nonzero_exit"
    return "completed"


def _summarize_tool_args(
    tool_name: str,
    kwargs: dict[str, Any],
    result: Any = None,
) -> dict[str, Any]:
    summary = dict(kwargs)
    if "content" in summary:
        summary["content"] = summarize_content(str(summary["content"]))
    if "command" in summary:
        cmd = str(summary["command"])
        if len(cmd) > COMMAND_AUDIT_TRUNCATE_CHARS:
            summary["command"] = (
                cmd[:COMMAND_AUDIT_TRUNCATE_CHARS] + "...[truncated]"
            )
    if result is not None and isinstance(result, dict):
        for key in ("bytes", "content_sha8", "created", "occurrences_replaced"):
            if key in result:
                summary[key] = result[key]
        if tool_name in EXEC_TOOL_NAMES:
            for key in (
                "exit_code",
                "duration_ms",
                "timed_out",
                "stdout_truncated",
                "stderr_truncated",
            ):
                if key in result:
                    summary[key] = result[key]
            # stdout/stderr riassunti (head+tail+sha) per non gonfiare l'audit.
            if "stdout" in result:
                summary["stdout"] = summarize_command_output(result["stdout"])
            if "stderr" in result:
                summary["stderr"] = summarize_command_output(result["stderr"])
    summary["tool"] = tool_name
    return summary


def _call_with_audit(
    audit: AuditLogger,
    tool_name: str,
    project_name: str | None,
    args: dict[str, Any],
    call: Callable[[], Any],
) -> Any:
    started = time.monotonic()
    token_id, client_ip = _request_context()

    try:
        result = call()
    except BaseException as exc:
        audit.log(
            _event_for_tool(tool_name, exc),
            _outcome_for_exception(exc),
            token_id=token_id,
            client_ip=client_ip,
            project=project_name,
            tool=tool_name,
            args=_summarize_tool_args(tool_name, args),
            duration_ms=(time.monotonic() - started) * 1000,
            error_class=exc.__class__.__name__,
            error_message=str(exc),
        )
        raise

    audit.log(
        f"tool.{tool_name}",
        "success",
        token_id=token_id,
        client_ip=client_ip,
        project=project_name,
        tool=tool_name,
        args=_summarize_tool_args(tool_name, args, result),
        duration_ms=(time.monotonic() - started) * 1000,
        outcome_detail=_outcome_detail_from_result(tool_name, result),
    )
    return result


def create_mcp(config: AppConfig, audit: AuditLogger | None = None) -> FastMCP:
    """Build FastMCP app and register implemented filesystem tools."""
    audit_logger = audit or AuditLogger(config.audit, config.server)
    mcp = FastMCP("devbox-bridge")

    @mcp.tool()
    async def list_projects() -> list[dict[str, Any]]:
        return cast(
            list[dict[str, Any]],
            _call_with_audit(
                audit_logger,
                "list_projects",
                None,
                {},
                lambda: filesystem.list_projects(config),
            ),
        )

    @mcp.tool()
    async def read_file(project: str, rel_path: str) -> dict[str, Any]:
        return cast(
            dict[str, Any],
            _call_with_audit(
                audit_logger,
                "read_file",
                project,
                {"project": project, "rel_path": rel_path},
                lambda: filesystem.read_file(config, project, rel_path),
            ),
        )

    @mcp.tool()
    async def write_file(
        project: str,
        rel_path: str,
        content: str,
        create: bool = False,
    ) -> dict[str, Any]:
        return cast(
            dict[str, Any],
            _call_with_audit(
                audit_logger,
                "write_file",
                project,
                {
                    "project": project,
                    "rel_path": rel_path,
                    "content": content,
                    "create": create,
                },
                lambda: filesystem.write_file(config, project, rel_path, content, create=create),
            ),
        )

    @mcp.tool()
    async def apply_patch(project: str, rel_path: str, old: str, new: str) -> dict[str, Any]:
        return cast(
            dict[str, Any],
            _call_with_audit(
                audit_logger,
                "apply_patch",
                project,
                {"project": project, "rel_path": rel_path, "old": old, "new": new},
                lambda: filesystem.apply_patch(config, project, rel_path, old, new),
            ),
        )

    @mcp.tool()
    async def list_directory(project: str, rel_path: str = ".") -> dict[str, Any]:
        return cast(
            dict[str, Any],
            _call_with_audit(
                audit_logger,
                "list_directory",
                project,
                {"project": project, "rel_path": rel_path},
                lambda: filesystem.list_directory(config, project, rel_path),
            ),
        )

    @mcp.tool()
    async def search_files(
        project: str,
        pattern: str,
        glob: str = "*",
        max_matches: int = 500,
    ) -> dict[str, Any]:
        return cast(
            dict[str, Any],
            _call_with_audit(
                audit_logger,
                "search_files",
                project,
                {
                    "project": project,
                    "pattern": pattern,
                    "glob": glob,
                    "max_matches": max_matches,
                },
                lambda: filesystem.search_files(
                    config,
                    project,
                    pattern,
                    glob=glob,
                    max_matches=max_matches,
                ),
            ),
        )

    @mcp.tool()
    async def git_status(project: str) -> dict[str, Any]:
        return cast(
            dict[str, Any],
            _call_with_audit(
                audit_logger,
                "git_status",
                project,
                {"project": project},
                lambda: git_tools.git_status(config, project),
            ),
        )

    @mcp.tool()
    async def git_diff(
        project: str,
        staged: bool = False,
        path: str | None = None,
    ) -> dict[str, Any]:
        return cast(
            dict[str, Any],
            _call_with_audit(
                audit_logger,
                "git_diff",
                project,
                {"project": project, "staged": staged, "path": path},
                lambda: git_tools.git_diff(
                    config, project, staged=staged, path=path
                ),
            ),
        )

    @mcp.tool()
    async def git_log(project: str, limit: int = 20) -> dict[str, Any]:
        return cast(
            dict[str, Any],
            _call_with_audit(
                audit_logger,
                "git_log",
                project,
                {"project": project, "limit": limit},
                lambda: git_tools.git_log(config, project, limit=limit),
            ),
        )

    @mcp.tool()
    async def git_branch_current(project: str) -> dict[str, Any]:
        return cast(
            dict[str, Any],
            _call_with_audit(
                audit_logger,
                "git_branch_current",
                project,
                {"project": project},
                lambda: git_tools.git_branch_current(config, project),
            ),
        )

    @mcp.tool()
    async def git_create_branch(project: str, name: str) -> dict[str, Any]:
        return cast(
            dict[str, Any],
            _call_with_audit(
                audit_logger,
                "git_create_branch",
                project,
                {"project": project, "name": name},
                lambda: git_tools.git_create_branch(config, project, name),
            ),
        )

    @mcp.tool()
    async def git_commit(
        project: str,
        message: str,
        paths: list[str],
    ) -> dict[str, Any]:
        return cast(
            dict[str, Any],
            _call_with_audit(
                audit_logger,
                "git_commit",
                project,
                {"project": project, "message": message, "paths": paths},
                lambda: git_tools.git_commit(config, project, message, paths),
            ),
        )

    @mcp.tool()
    async def git_push(project: str, remote: str = "origin") -> dict[str, Any]:
        return cast(
            dict[str, Any],
            _call_with_audit(
                audit_logger,
                "git_push",
                project,
                {"project": project, "remote": remote},
                lambda: git_tools.git_push(config, project, remote=remote),
            ),
        )

    @mcp.tool()
    async def run_command(
        project: str,
        command: str,
        timeout: int = DEFAULT_RUN_COMMAND_TIMEOUT_SECONDS,
    ) -> dict[str, Any]:
        return cast(
            dict[str, Any],
            _call_with_audit(
                audit_logger,
                "run_command",
                project,
                {"project": project, "command": command, "timeout": timeout},
                lambda: execution.run_command(
                    config, project, command, timeout=timeout
                ),
            ),
        )

    @mcp.tool()
    async def run_tests(project: str) -> dict[str, Any]:
        return cast(
            dict[str, Any],
            _call_with_audit(
                audit_logger,
                "run_tests",
                project,
                {"project": project},
                lambda: execution.run_tests(config, project),
            ),
        )

    @mcp.tool()
    async def run_lint(project: str) -> dict[str, Any]:
        return cast(
            dict[str, Any],
            _call_with_audit(
                audit_logger,
                "run_lint",
                project,
                {"project": project},
                lambda: execution.run_lint(config, project),
            ),
        )

    @mcp.tool()
    async def run_build(project: str) -> dict[str, Any]:
        return cast(
            dict[str, Any],
            _call_with_audit(
                audit_logger,
                "run_build",
                project,
                {"project": project},
                lambda: execution.run_build(config, project),
            ),
        )

    @mcp.tool()
    async def get_system_info() -> dict[str, Any]:
        return cast(
            dict[str, Any],
            _call_with_audit(
                audit_logger,
                "get_system_info",
                None,
                {},
                lambda: system.get_system_info(),
            ),
        )

    @mcp.tool()
    async def list_systemd_services(
        name_filter: str | None = None,
    ) -> dict[str, Any]:
        return cast(
            dict[str, Any],
            _call_with_audit(
                audit_logger,
                "list_systemd_services",
                None,
                {"name_filter": name_filter},
                lambda: system.list_systemd_services(config, name_filter=name_filter),
            ),
        )

    @mcp.tool()
    async def tail_log(path: str, lines: int = DEFAULT_LOG_LINES) -> dict[str, Any]:
        return cast(
            dict[str, Any],
            _call_with_audit(
                audit_logger,
                "tail_log",
                None,
                {"path": path, "lines": lines},
                lambda: system.tail_log(config, path, lines=lines),
            ),
        )

    @mcp.tool()
    async def read_journalctl(
        unit: str, lines: int = DEFAULT_LOG_LINES
    ) -> dict[str, Any]:
        return cast(
            dict[str, Any],
            _call_with_audit(
                audit_logger,
                "read_journalctl",
                None,
                {"unit": unit, "lines": lines},
                lambda: system.read_journalctl(config, unit, lines=lines),
            ),
        )

    return mcp


def create_http_app(config: AppConfig, audit: AuditLogger | None = None) -> Any:
    """Build the authenticated Starlette app used by uvicorn/tests."""
    audit_logger = audit or AuditLogger(config.audit, config.server)
    authenticator = Authenticator(config.auth.token_hash_file)
    mcp = create_mcp(config, audit_logger)
    return mcp.http_app(
        path=MCP_HTTP_PATH,
        transport="http",
        middleware=[
            ASGIMiddleware(
                BearerAuthMiddleware,
                authenticator=authenticator,
                audit=audit_logger,
            )
        ],
    )


def _split_bind(bind: str) -> tuple[str, int]:
    host, port_text = bind.rsplit(":", 1)
    return host, int(port_text)


def load_config_from_env() -> AppConfig:
    return load_config(Path(os.environ.get(CONFIG_ENV_VAR, DEFAULT_CONFIG_PATH)))


def main() -> None:
    config = load_config_from_env()
    audit_logger = AuditLogger(config.audit, config.server)
    authenticator = Authenticator(config.auth.token_hash_file)
    mcp = create_mcp(config, audit_logger)
    host, port = _split_bind(config.server.bind)
    mcp.run(
        transport="http",
        host=host,
        port=port,
        path=MCP_HTTP_PATH,
        log_level=config.server.log_level.lower(),
        middleware=[
            ASGIMiddleware(
                BearerAuthMiddleware,
                authenticator=authenticator,
                audit=audit_logger,
            )
        ],
    )


if __name__ == "__main__":
    main()
