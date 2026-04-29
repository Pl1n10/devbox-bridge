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

from devbox_bridge.audit import AuditLogger, summarize_content
from devbox_bridge.auth import Authenticator, AuthFailed, RateLimitExceeded, token_log_id
from devbox_bridge.config import AppConfig, load_config
from devbox_bridge.security.paths import PathSecurityError
from devbox_bridge.tools import filesystem
from devbox_bridge.tools import git as git_tools
from devbox_bridge.tools.filesystem import GlobSecurityError, WriteNotAllowedError
from devbox_bridge.tools.git import PushNotAllowedError

CONFIG_ENV_VAR = "DEVBOX_BRIDGE_CONFIG"
DEFAULT_CONFIG_PATH = "config.yaml"
MCP_HTTP_PATH = "/mcp"
RETRY_AFTER_SECONDS = "60"


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
    if isinstance(exc, (PathSecurityError, GlobSecurityError, WriteNotAllowedError)):
        return "path.rejected"
    return f"tool.{tool_name}"


def _outcome_for_exception(exc: BaseException) -> str:
    if isinstance(
        exc,
        (
            PathSecurityError,
            GlobSecurityError,
            WriteNotAllowedError,
            PushNotAllowedError,
        ),
    ):
        return "denied"
    return "error"


def _summarize_tool_args(
    tool_name: str,
    kwargs: dict[str, Any],
    result: Any = None,
) -> dict[str, Any]:
    summary = dict(kwargs)
    if "content" in summary:
        summary["content"] = summarize_content(str(summary["content"]))
    if result is not None and isinstance(result, dict):
        for key in ("bytes", "content_sha8", "created", "occurrences_replaced"):
            if key in result:
                summary[key] = result[key]
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
