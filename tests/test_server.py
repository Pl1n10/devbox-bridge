"""Test per server.py — FastMCP registration, auth middleware, audit mapping."""

from __future__ import annotations

import json
import sys
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

PYTHON = sys.executable


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
async def test_create_mcp_registers_git_tools(config_ro: AppConfig) -> None:
    mcp = create_mcp(config_ro, _audit(config_ro))
    tool_names = {tool.name for tool in await mcp.list_tools()}
    assert {
        "git_status",
        "git_diff",
        "git_log",
        "git_branch_current",
        "git_create_branch",
        "git_commit",
        "git_push",
    } <= tool_names


@pytest.mark.asyncio
async def test_git_push_denied_audited_as_tool_event(
    config_git_rw: AppConfig,
) -> None:
    """allow_push=False → PushNotAllowedError → outcome=denied, event=tool.git_push."""
    log = _audit(config_git_rw)
    mcp = create_mcp(config_git_rw, log)

    with pytest.raises(ToolError):
        await mcp.call_tool("git_push", {"project": "gitproj"})

    lines = _audit_lines(log)
    assert len(lines) == 1
    assert lines[0]["event"] == "tool.git_push"
    assert lines[0]["outcome"] == "denied"
    assert lines[0]["error_class"] == "PushNotAllowedError"


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


@pytest.mark.asyncio
async def test_create_mcp_registers_execution_tools(config_ro: AppConfig) -> None:
    mcp = create_mcp(config_ro, _audit(config_ro))
    tool_names = {tool.name for tool in await mcp.list_tools()}
    assert {"run_command", "run_tests", "run_lint", "run_build"} <= tool_names


@pytest.mark.asyncio
async def test_run_command_success_audits_outcome_detail_completed(
    config_factory: Any, tmp_project_root: Path
) -> None:
    cfg = config_factory(
        tmp_project_root,
        write_enabled=True,
        command_whitelist=[r"^.+ -c .+$"],
    )
    log = _audit(cfg)
    mcp = create_mcp(cfg, log)

    result = await mcp.call_tool(
        "run_command",
        {
            "project": "myproj",
            "command": f"{PYTHON} -c 'print(\"hi\")'",
        },
    )
    assert result.structured_content["exit_code"] == 0

    lines = _audit_lines(log)
    assert len(lines) == 1
    assert lines[0]["event"] == "tool.run_command"
    assert lines[0]["outcome"] == "success"
    assert lines[0]["outcome_detail"] == "completed"
    # stdout/stderr riassunti, non inseriti raw
    assert "total_sha8" in lines[0]["args_summary"]["stdout"]


@pytest.mark.asyncio
async def test_run_command_denied_audits_command_rejected(
    config_factory: Any, tmp_project_root: Path
) -> None:
    """rm -rf / passa la whitelist permissiva ma è bloccato dalla deny list →
    event=command.rejected, outcome=denied."""
    cfg = config_factory(
        tmp_project_root,
        write_enabled=True,
        command_whitelist=[r"^.*$"],
    )
    log = _audit(cfg)
    mcp = create_mcp(cfg, log)

    with pytest.raises(ToolError):
        await mcp.call_tool(
            "run_command",
            {"project": "myproj", "command": "rm -rf /"},
        )

    lines = _audit_lines(log)
    assert len(lines) == 1
    assert lines[0]["event"] == "command.rejected"
    assert lines[0]["outcome"] == "denied"
    assert lines[0]["error_class"] == "CommandRejectedError"
    assert lines[0]["outcome_detail"] is None


@pytest.mark.asyncio
async def test_create_mcp_registers_system_tools(config_ro: AppConfig) -> None:
    mcp = create_mcp(config_ro, _audit(config_ro))
    tool_names = {tool.name for tool in await mcp.list_tools()}
    assert {
        "get_system_info",
        "list_systemd_services",
        "tail_log",
        "read_journalctl",
    } <= tool_names


@pytest.mark.asyncio
async def test_tail_log_denied_audited_as_path_rejected(
    tmp_path: Path,
    tmp_token_file: Path,
) -> None:
    """tail_log su path fuori whitelist → outcome=denied.
    Read-tool denied → audit emesso (denied/error sempre auditati anche con
    audit_reads=false)."""
    from devbox_bridge.config import (
        AppConfig,
        AuditConfig,
        AuthConfig,
        ServerConfig,
        SystemConfig,
    )

    log_dir = tmp_path / "wlog"
    log_dir.mkdir()
    cfg = AppConfig(
        server=ServerConfig(log_dir=tmp_path / "logs"),
        auth=AuthConfig(token_hash_file=tmp_token_file),
        audit=AuditConfig(log_dir=tmp_path / "logs" / "audit"),
        system=SystemConfig(log_paths_whitelist=[log_dir]),
    )
    log = _audit(cfg)
    mcp = create_mcp(cfg, log)

    # Path fuori dalla whitelist
    with pytest.raises(ToolError):
        await mcp.call_tool(
            "tail_log",
            {"path": "/etc/passwd"},
        )

    lines = _audit_lines(log)
    assert len(lines) == 1
    assert lines[0]["event"] == "path.rejected"
    assert lines[0]["outcome"] == "denied"
    assert lines[0]["error_class"] == "LogPathNotAllowedError"


@pytest.mark.asyncio
async def test_get_system_info_read_not_audited_by_default(
    config_ro: AppConfig,
) -> None:
    """audit_reads=false (default) → tool.get_system_info success NON auditato."""
    log = _audit(config_ro)
    mcp = create_mcp(config_ro, log)

    result = await mcp.call_tool("get_system_info", {})
    assert "hostname" in result.structured_content
    # audit_reads=false: read tool success non auditato.
    assert _audit_lines(log) == []


@pytest.mark.asyncio
async def test_run_command_long_command_truncated_in_audit(
    config_factory: Any, tmp_project_root: Path
) -> None:
    """Comando >500 char nei kwargs viene troncato in args_summary
    (protezione log poisoning). Il 'rm -rf /' resta visibile nel troncato
    perché è nei primi 500 char."""
    cfg = config_factory(
        tmp_project_root,
        write_enabled=True,
        command_whitelist=[r"^.*$"],
    )
    log = _audit(cfg)
    mcp = create_mcp(cfg, log)
    huge = "rm -rf / " + "A" * 1000

    with pytest.raises(ToolError):
        await mcp.call_tool(
            "run_command",
            {"project": "myproj", "command": huge},
        )

    lines = _audit_lines(log)
    assert "...[truncated]" in lines[0]["args_summary"]["command"]
    assert len(lines[0]["args_summary"]["command"]) < len(huge)
