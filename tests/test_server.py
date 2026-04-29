"""Test per server.py — FastMCP registration, auth middleware, audit mapping."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastmcp.exceptions import ToolError
from starlette.applications import Starlette
from starlette.middleware import Middleware as ASGIMiddleware
from starlette.requests import Request
from starlette.responses import PlainTextResponse
from starlette.routing import Route

from devbox_bridge.audit import AuditLogger
from devbox_bridge.auth import Authenticator
from devbox_bridge.config import AppConfig
from devbox_bridge.server import (
    BearerAuthMiddleware,
    _client_ip_from_request,
    _extract_bearer_token,
    _split_bind,
    create_http_app,
    create_mcp,
)


def _audit(config: AppConfig) -> AuditLogger:
    return AuditLogger(config.audit, config.server)


def _audit_lines(log: AuditLogger) -> list[dict[str, Any]]:
    if not log.current_log_path.exists():
        return []
    return [
        json.loads(line)
        for line in log.current_log_path.read_text(encoding="utf-8").splitlines()
    ]


def test_extract_bearer_token() -> None:
    assert _extract_bearer_token("Bearer abc123") == "abc123"
    assert _extract_bearer_token("bearer abc123") == "abc123"
    assert _extract_bearer_token("Basic abc123") is None
    assert _extract_bearer_token("Bearer") is None
    assert _extract_bearer_token(None) is None


def test_split_bind() -> None:
    assert _split_bind("127.0.0.1:8765") == ("127.0.0.1", 8765)


def test_create_http_app_uses_mcp_path(config_ro: AppConfig) -> None:
    app = create_http_app(config_ro, _audit(config_ro))
    assert app.state.path == "/mcp"


@pytest.mark.asyncio
async def test_create_mcp_registers_filesystem_tools(config_ro: AppConfig) -> None:
    mcp = create_mcp(config_ro, _audit(config_ro))
    tool_names = {tool.name for tool in await mcp.list_tools()}
    assert {
        "list_projects",
        "read_file",
        "write_file",
        "apply_patch",
        "list_directory",
        "search_files",
    } <= tool_names


@pytest.mark.asyncio
async def test_read_file_tool_returns_structured_content(config_ro: AppConfig) -> None:
    log = _audit(config_ro)
    mcp = create_mcp(config_ro, log)

    result = await mcp.call_tool(
        "read_file",
        {"project": "myproj", "rel_path": "README.md"},
    )

    assert result.structured_content["path"] == "README.md"
    assert "Hello world" in result.structured_content["content"]
    # audit_reads=false: read tools do not emit audit lines by default.
    assert _audit_lines(log) == []


@pytest.mark.asyncio
async def test_write_file_tool_audits_success(
    config_rw: AppConfig,
    tmp_project_root: Path,
) -> None:
    log = _audit(config_rw)
    mcp = create_mcp(config_rw, log)

    result = await mcp.call_tool(
        "write_file",
        {
            "project": "myproj",
            "rel_path": "src/server_created.py",
            "content": "x = 1\n",
            "create": True,
        },
    )

    assert result.structured_content["created"] is True
    assert (tmp_project_root / "src" / "server_created.py").read_text() == "x = 1\n"
    lines = _audit_lines(log)
    assert len(lines) == 1
    assert lines[0]["event"] == "tool.write_file"
    assert lines[0]["outcome"] == "success"
    assert lines[0]["args_summary"]["content"]["bytes"] == 6


@pytest.mark.asyncio
async def test_write_file_denied_audits_path_rejected(config_ro: AppConfig) -> None:
    log = _audit(config_ro)
    mcp = create_mcp(config_ro, log)

    with pytest.raises(ToolError):
        await mcp.call_tool(
            "write_file",
            {
                "project": "myproj",
                "rel_path": "README.md",
                "content": "blocked",
            },
        )

    lines = _audit_lines(log)
    assert len(lines) == 1
    assert lines[0]["event"] == "path.rejected"
    assert lines[0]["outcome"] == "denied"
    assert lines[0]["error_class"] == "WriteNotAllowedError"


@pytest.mark.asyncio
async def test_bearer_auth_middleware_rejects_missing_token(config_ro: AppConfig) -> None:
    log = _audit(config_ro)
    authenticator = Authenticator(config_ro.auth.token_hash_file)

    async def endpoint(_request):
        return PlainTextResponse("ok")

    app = Starlette(
        routes=[Route("/", endpoint)],
        middleware=[
            ASGIMiddleware(
                BearerAuthMiddleware,
                authenticator=authenticator,
                audit=log,
            )
        ],
    )

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/")

    assert response.status_code == 401
    assert response.text == "unauthorized"
    lines = _audit_lines(log)
    assert lines[0]["event"] == "auth.failed"
    assert lines[0]["error_message"] == "unauthorized"


@pytest.mark.asyncio
async def test_bearer_auth_middleware_allows_valid_token(config_ro: AppConfig) -> None:
    log = _audit(config_ro)
    authenticator = Authenticator(config_ro.auth.token_hash_file)

    async def endpoint(_request):
        return PlainTextResponse("ok")

    app = Starlette(
        routes=[Route("/", endpoint)],
        middleware=[
            ASGIMiddleware(
                BearerAuthMiddleware,
                authenticator=authenticator,
                audit=log,
            )
        ],
    )

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get(
            "/",
            headers={
                "authorization": "Bearer test-token-123",
                "x-forwarded-for": "203.0.113.10, 10.0.0.1",
            },
        )

    assert response.status_code == 200
    assert response.text == "ok"
    assert _audit_lines(log) == []


@pytest.mark.asyncio
async def test_bearer_auth_middleware_rate_limit_returns_retry_after(
    config_ro: AppConfig,
) -> None:
    log = _audit(config_ro)
    authenticator = Authenticator(config_ro.auth.token_hash_file, rate_limit_per_minute=1)

    async def endpoint(_request):
        return PlainTextResponse("ok")

    app = Starlette(
        routes=[Route("/", endpoint)],
        middleware=[
            ASGIMiddleware(
                BearerAuthMiddleware,
                authenticator=authenticator,
                audit=log,
            )
        ],
    )

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        headers = {"authorization": "Bearer test-token-123"}
        assert (await client.get("/", headers=headers)).status_code == 200
        response = await client.get("/", headers=headers)

    assert response.status_code == 429
    assert response.headers["retry-after"] == "60"
    assert response.text == "too many requests"
    lines = _audit_lines(log)
    assert len(lines) == 1
    assert lines[0]["event"] == "auth.rate_limited"


def test_client_ip_uses_x_forwarded_for_first_entry() -> None:
    request = Request(
        {
            "type": "http",
            "headers": [(b"x-forwarded-for", b"203.0.113.10, 10.0.0.1")],
            "client": ("127.0.0.1", 12345),
        }
    )
    assert _client_ip_from_request(request) == "203.0.113.10"


def test_client_ip_invalid_value_is_marked() -> None:
    request = Request(
        {
            "type": "http",
            "headers": [(b"x-forwarded-for", b"not-an-ip")],
            "client": ("127.0.0.1", 12345),
        }
    )
    assert _client_ip_from_request(request) == "(invalid)"
