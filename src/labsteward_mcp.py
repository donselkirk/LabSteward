#!/usr/bin/env python3
"""Authenticated, TLS-only Streamable HTTP MCP transport for LabSteward."""

from __future__ import annotations

import argparse
import collections
import hashlib
import hmac
import ipaddress
import json
import os
import re
import ssl
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from labsteward_core import DispatchError, dispatch_action, tool_definitions

BASE_DIR = Path(os.environ.get("LABSTEWARD_BASE_DIR", "/opt/labsteward"))
CONFIG_FILE = Path(os.environ.get("LABSTEWARD_CONFIG_FILE", "/etc/labsteward/config.json"))
CLIENT_SECRETS_DIR = Path(
    os.environ.get("LABSTEWARD_CLIENT_SECRETS_DIR", "/etc/labsteward/secrets/clients")
)
OAUTH_TOKEN_FILE = Path(
    os.environ.get("LABSTEWARD_OAUTH_TOKEN_FILE", "/etc/labsteward/secrets/oauth-tokens.json")
)
VERSION_FILE = Path(os.environ.get("LABSTEWARD_VERSION_FILE", str(BASE_DIR / "VERSION")))
DEFAULT_TRANSPORT_CONFIG = Path(
    os.environ.get("LABSTEWARD_TRANSPORT_CONFIG", "/etc/labsteward/transport.json")
)

MAX_REQUEST_BYTES = 64 * 1024
MAX_JSON_FILE_BYTES = 1024 * 1024
RATE_LIMIT_REQUESTS = 60
RATE_LIMIT_WINDOW_SECONDS = 60
MAX_RATE_LIMIT_SOURCES = 1024
MAX_CONCURRENT_CONNECTIONS = 32
CONNECTION_TIMEOUT_SECONDS = 15
SUPPORTED_PROTOCOL_VERSIONS = (
    "2025-06-18",
    "2025-03-26",
    "2024-11-05",
)
SERVER_NAME = "labsteward"
HOSTNAME = re.compile(
    r"^(?=.{1,253}\.?$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.?$",
    re.IGNORECASE,
)


def audit(event: str, **fields: object) -> None:
    record = {"event": event, "service": SERVER_NAME, **fields}
    print(json.dumps(record, separators=(",", ":"), sort_keys=True), file=sys.stderr, flush=True)


def reject_json_constant(value: str) -> None:
    raise ValueError(f"invalid JSON constant: {value}")


def read_object(path: Path) -> dict[str, Any]:
    if path.stat().st_size > MAX_JSON_FILE_BYTES:
        raise ValueError(f"oversized JSON file: {path}")
    value = json.loads(path.read_text(encoding="utf-8"), parse_constant=reject_json_constant)
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value


def normalize_address(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    address = ipaddress.ip_address(value)
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        return address.ipv4_mapped
    return address


def source_allowed(source: str, networks: object) -> bool:
    try:
        address = normalize_address(source)
    except ValueError:
        return False
    if not isinstance(networks, list):
        return False
    for item in networks:
        try:
            network = ipaddress.ip_network(item, strict=False)
        except (TypeError, ValueError):
            continue
        if address.version == network.version and address in network:
            return True
    return False


def authenticate_client(token: str, source: str) -> str | None:
    """Return an enabled client ID only when token and socket source both match."""

    try:
        config = read_object(CONFIG_FILE)
    except (OSError, ValueError, json.JSONDecodeError):
        return None
    clients = config.get("clients", {})
    if not isinstance(clients, dict):
        return None
    candidate = hashlib.sha256(token.encode("utf-8")).hexdigest()
    matched_id: str | None = None
    matched_sources: object = None
    if token.startswith("lst_"):
        # Compare every legacy verifier so timing does not reveal its position.
        for client_id, client in sorted(clients.items()):
            if not isinstance(client_id, str) or not isinstance(client, dict):
                continue
            digest = "0" * 64
            try:
                record = read_object(CLIENT_SECRETS_DIR / f"{client_id}.json")
                stored = record.get("digest")
                if (
                    record.get("schema") == 1
                    and record.get("algorithm") == "sha256"
                    and isinstance(stored, str)
                    and re.fullmatch(r"[a-f0-9]{64}", stored)
                ):
                    digest = stored
            except (OSError, ValueError, json.JSONDecodeError):
                pass
            token_matches = hmac.compare_digest(candidate, digest)
            if (
                token_matches
                and client.get("enabled") is True
                and client.get("auth", "legacy_token") == "legacy_token"
            ):
                matched_id = client_id
                matched_sources = client.get("sources")
    elif token.startswith("lsa_"):
        now = int(time.time())
        try:
            snapshot = read_object(OAUTH_TOKEN_FILE)
            entries = snapshot.get("tokens", []) if snapshot.get("schema") == 1 else []
        except (OSError, ValueError, json.JSONDecodeError):
            entries = []
        if isinstance(entries, list):
            for entry in entries:
                digest = "0" * 64
                client_id = ""
                expiry = 0
                if isinstance(entry, dict):
                    stored = entry.get("digest")
                    if isinstance(stored, str) and re.fullmatch(r"[a-f0-9]{64}", stored):
                        digest = stored
                    if isinstance(entry.get("client"), str):
                        client_id = entry["client"]
                    if isinstance(entry.get("expires_at"), int):
                        expiry = entry["expires_at"]
                token_matches = hmac.compare_digest(candidate, digest)
                client = clients.get(client_id)
                if (
                    token_matches
                    and expiry > now
                    and isinstance(client, dict)
                    and client.get("enabled") is True
                    and client.get("auth") == "oauth"
                ):
                    matched_id = client_id
                    matched_sources = client.get("sources")
    if matched_id is None or not source_allowed(source, matched_sources):
        return None
    return matched_id


def parse_bearer(value: str | None) -> str | None:
    if not value or not value.startswith("Bearer "):
        return None
    token = value[7:]
    if not re.fullmatch(r"(?:lst|lsa)_[A-Za-z0-9_-]{43}", token):
        return None
    return token


def validate_transport_config(
    config: dict[str, Any],
) -> tuple[str, int, list[str], Path, Path, str | None, list[str]]:
    if config.get("schema") != 1:
        raise ValueError("unsupported transport configuration schema")
    bind = config.get("bind")
    port = config.get("port")
    allowed_hosts = config.get("allowed_hosts")
    cert_file = config.get("cert_file")
    key_file = config.get("key_file")
    try:
        address = normalize_address(bind)
    except (TypeError, ValueError) as exc:
        raise ValueError("transport bind must be a literal IP address") from exc
    if address.is_unspecified or address.is_multicast:
        raise ValueError("transport bind cannot be unspecified or multicast")
    if not isinstance(port, int) or not 1024 <= port <= 65535:
        raise ValueError("transport port must be between 1024 and 65535")
    if not isinstance(allowed_hosts, list) or not allowed_hosts or len(allowed_hosts) > 16:
        raise ValueError("transport must define one to sixteen allowed hosts")
    normalized_hosts: list[str] = []
    for host in allowed_hosts:
        if not isinstance(host, str) or not HOSTNAME.fullmatch(host):
            try:
                ipaddress.ip_address(host)
            except (TypeError, ValueError) as exc:
                raise ValueError("transport contains an invalid allowed host") from exc
        normalized_hosts.append(host.lower().rstrip("."))
    if not isinstance(cert_file, str) or not isinstance(key_file, str):
        raise ValueError("transport TLS paths are invalid")
    cert_path = Path(cert_file)
    key_path = Path(key_file)
    if not cert_path.is_absolute() or not key_path.is_absolute():
        raise ValueError("transport TLS paths must be absolute")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(cert_path, key_path)
    resource = config.get("resource")
    authorization_servers = config.get("authorization_servers", [])
    if resource is None and authorization_servers == []:
        return str(address), port, normalized_hosts, cert_path, key_path, None, []
    parsed_resource = urlsplit(resource if isinstance(resource, str) else "")
    try:
        resource_port = parsed_resource.port
    except ValueError as exc:
        raise ValueError("transport OAuth resource is invalid") from exc
    if (
        parsed_resource.scheme != "https"
        or not parsed_resource.hostname
        or parsed_resource.path != "/mcp"
        or parsed_resource.query
        or parsed_resource.fragment
        or parsed_resource.username
        or parsed_resource.password
    ):
        raise ValueError("transport OAuth resource is invalid")
    if not isinstance(authorization_servers, list) or not authorization_servers or len(authorization_servers) > 4:
        raise ValueError("transport OAuth authorization server list is invalid")
    normalized_authorization_servers = []
    for item in authorization_servers:
        parsed = urlsplit(item if isinstance(item, str) else "")
        try:
            authorization_port = parsed.port
        except ValueError as exc:
            raise ValueError("transport OAuth authorization server is invalid") from exc
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.path not in ("", "/")
            or parsed.query
            or parsed.fragment
            or parsed.username
            or parsed.password
        ):
            raise ValueError("transport OAuth authorization server is invalid")
        normalized_authorization_servers.append(str(item).rstrip("/"))
    return (
        str(address), port, normalized_hosts, cert_path, key_path,
        str(resource), normalized_authorization_servers,
    )


class SourceRateLimiter:
    def __init__(self) -> None:
        self._entries: dict[str, collections.deque[float]] = {}
        self._lock = threading.Lock()

    def allow(self, source: str) -> bool:
        now = time.monotonic()
        cutoff = now - RATE_LIMIT_WINDOW_SECONDS
        with self._lock:
            if source not in self._entries and len(self._entries) >= MAX_RATE_LIMIT_SOURCES:
                oldest = min(
                    self._entries,
                    key=lambda item: self._entries[item][-1] if self._entries[item] else 0,
                )
                self._entries.pop(oldest, None)
            history = self._entries.setdefault(source, collections.deque())
            while history and history[0] < cutoff:
                history.popleft()
            if len(history) >= RATE_LIMIT_REQUESTS:
                return False
            history.append(now)
            return True


class LabStewardHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, server_address: tuple[str, int], handler: type[BaseHTTPRequestHandler]):
        super().__init__(server_address, handler)
        self.allowed_hosts: list[str] = []
        self.resource: str | None = None
        self.authorization_servers: list[str] = []
        self.rate_limiter = SourceRateLimiter()
        self.ssl_context: ssl.SSLContext | None = None
        self.connection_slots = threading.BoundedSemaphore(MAX_CONCURRENT_CONNECTIONS)

    def process_request(self, request: Any, client_address: tuple[str, int]) -> None:
        if not self.connection_slots.acquire(blocking=False):
            audit("connection_rejected", source=client_address[0], reason="concurrency_limit")
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self.connection_slots.release()
            raise

    def process_request_thread(self, request: Any, client_address: tuple[str, int]) -> None:
        tls_request = None
        try:
            request.settimeout(CONNECTION_TIMEOUT_SECONDS)
            if self.ssl_context is None:
                raise ssl.SSLError("TLS context is unavailable")
            tls_request = self.ssl_context.wrap_socket(request, server_side=True)
            super().process_request_thread(tls_request, client_address)
        except (OSError, ssl.SSLError):
            audit("tls_handshake_failed", source=client_address[0])
            try:
                request.close()
            except OSError:
                pass
        finally:
            self.connection_slots.release()


class MCPHandler(BaseHTTPRequestHandler):
    server_version = "LabSteward"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    def log_message(self, _format: str, *_args: object) -> None:
        # All logs are emitted through the controlled audit function.
        return

    @property
    def source(self) -> str:
        try:
            return str(normalize_address(self.client_address[0]))
        except ValueError:
            return "invalid"

    def send_empty(self, status: int, *, authenticate: bool = False) -> None:
        self.close_connection = True
        self.send_response(status)
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        if authenticate:
            challenge = 'Bearer realm="labsteward"'
            resource = self.server.resource  # type: ignore[attr-defined]
            if resource:
                metadata_url = resource.rsplit("/mcp", 1)[0] + "/.well-known/oauth-protected-resource/mcp"
                challenge += f', resource_metadata="{metadata_url}"'
            self.send_header("WWW-Authenticate", challenge)
        self.send_header("Connection", "close")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def send_json(self, status: int, payload: dict[str, Any]) -> None:
        self.close_connection = True
        body = json.dumps(payload, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Connection", "close")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def jsonrpc_error(self, request_id: object, code: int, message: str) -> None:
        self.send_json(
            200,
            {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}},
        )

    def host_allowed(self) -> bool:
        host_header = self.headers.get("Host", "")
        if host_header.startswith("["):
            host = host_header[1:].split("]", 1)[0]
        else:
            host = host_header.rsplit(":", 1)[0]
        return host.lower().rstrip(".") in self.server.allowed_hosts  # type: ignore[attr-defined]

    def do_GET(self) -> None:  # noqa: N802
        source = self.source
        if not self.server.rate_limiter.allow(source):  # type: ignore[attr-defined]
            self.send_empty(429)
            return
        if not self.host_allowed() or self.headers.get("Origin") is not None:
            self.send_empty(403)
            return
        if self.path in {
            "/.well-known/oauth-protected-resource",
            "/.well-known/oauth-protected-resource/mcp",
        } and self.server.resource:  # type: ignore[attr-defined]
            self.send_json(
                200,
                {
                    "resource": self.server.resource,  # type: ignore[attr-defined]
                    "authorization_servers": self.server.authorization_servers,  # type: ignore[attr-defined]
                    "bearer_methods_supported": ["header"],
                    "scopes_supported": ["mcp:connect"],
                },
            )
            return
        self.send_empty(404)

    def do_DELETE(self) -> None:  # noqa: N802
        self.send_empty(405)

    def do_POST(self) -> None:  # noqa: N802
        source = self.source
        if self.path != "/mcp":
            self.send_empty(404)
            return
        if not self.server.rate_limiter.allow(source):  # type: ignore[attr-defined]
            audit("request_rejected", source=source, reason="rate_limit")
            self.send_empty(429)
            return
        if not self.host_allowed() or self.headers.get("Origin") is not None:
            audit("request_rejected", source=source, reason="host_or_origin")
            self.send_empty(403)
            return
        token = parse_bearer(self.headers.get("Authorization"))
        client_id = authenticate_client(token or "", source) if token else None
        if client_id is None:
            audit("authentication_failed", source=source)
            self.send_empty(401, authenticate=True)
            return
        content_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        if content_type != "application/json":
            self.send_empty(415)
            return
        if self.headers.get("Transfer-Encoding") is not None:
            self.send_empty(400)
            return
        lengths = self.headers.get_all("Content-Length", [])
        if len(lengths) != 1:
            self.send_empty(411)
            return
        length_text = lengths[0]
        try:
            length = int(length_text or "")
        except ValueError:
            self.send_empty(411)
            return
        if length < 1 or length > MAX_REQUEST_BYTES:
            self.send_empty(413)
            return
        try:
            request = json.loads(
                self.rfile.read(length),
                parse_constant=reject_json_constant,
            )
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError):
            self.jsonrpc_error(None, -32700, "Parse error")
            return
        if not isinstance(request, dict) or request.get("jsonrpc") != "2.0":
            self.jsonrpc_error(None, -32600, "Invalid request")
            return
        method = request.get("method")
        request_id = request.get("id")
        if not isinstance(method, str):
            self.jsonrpc_error(request_id, -32600, "Invalid request")
            return
        if request_id is not None and (
            isinstance(request_id, bool) or not isinstance(request_id, (str, int))
        ):
            self.jsonrpc_error(None, -32600, "Invalid request")
            return
        if request_id is None:
            if method in {"notifications/initialized", "notifications/cancelled"}:
                audit("notification_accepted", source=source, client=client_id, method=method)
                self.send_empty(202)
                return
            self.send_empty(202)
            return
        try:
            result = self.dispatch(method, request.get("params", {}))
        except DispatchError as exc:
            audit(
                "tool_rejected",
                source=source,
                client=client_id,
                method=method,
                reason=exc.code,
            )
            if method == "tools/call":
                result = {
                    "content": [{"type": "text", "text": exc.message}],
                    "isError": True,
                }
            else:
                self.jsonrpc_error(request_id, -32602, exc.message)
                return
        except Exception:
            audit("request_failed", source=source, client=client_id, method=method)
            self.jsonrpc_error(request_id, -32603, "Internal error")
            return
        audit("request_succeeded", source=source, client=client_id, method=method)
        self.send_json(200, {"jsonrpc": "2.0", "id": request_id, "result": result})

    def dispatch(self, method: str, params: object) -> dict[str, Any]:
        if method == "initialize":
            if not isinstance(params, dict):
                raise DispatchError("invalid_arguments", "Invalid initialize parameters")
            requested = params.get("protocolVersion")
            version = requested if requested in SUPPORTED_PROTOCOL_VERSIONS else SUPPORTED_PROTOCOL_VERSIONS[0]
            try:
                release = VERSION_FILE.read_text(encoding="utf-8").strip()
            except OSError:
                release = "development"
            return {
                "protocolVersion": version,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": SERVER_NAME, "version": release},
                "instructions": (
                    "LabSteward exposes only fixed, permission-checked home-lab actions. "
                    "Never infer arbitrary command, URL, file, or credential access. "
                    "core_status is read-only and contacts no managed server."
                ),
            }
        if method == "ping":
            return {}
        if method == "tools/list":
            return {"tools": tool_definitions()}
        if method == "tools/call":
            if not isinstance(params, dict):
                raise DispatchError("invalid_arguments", "Invalid tool call")
            name = params.get("name")
            arguments = params.get("arguments", {})
            if name != "core_status":
                raise DispatchError("unknown_action", "Unknown LabSteward tool")
            result = dispatch_action("core.status", arguments)
            return {
                "content": [
                    {
                        "type": "text",
                        "text": json.dumps(result, separators=(",", ":"), sort_keys=True),
                    }
                ],
                "structuredContent": result,
                "isError": False,
            }
        raise DispatchError("unknown_method", "Method not found")


def build_server(config_path: Path) -> tuple[LabStewardHTTPServer, ssl.SSLContext]:
    config = read_object(config_path)
    bind, port, allowed_hosts, cert_path, key_path, resource, authorization_servers = validate_transport_config(config)
    server = LabStewardHTTPServer((bind, port), MCPHandler)
    server.allowed_hosts = allowed_hosts
    server.resource = resource
    server.authorization_servers = authorization_servers
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.options |= ssl.OP_NO_COMPRESSION
    context.load_cert_chain(cert_path, key_path)
    server.ssl_context = context
    return server, context


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the LabSteward MCP transport")
    parser.add_argument("--config", type=Path, default=DEFAULT_TRANSPORT_CONFIG)
    parser.add_argument("--check-config", action="store_true")
    args = parser.parse_args()
    try:
        config = read_object(args.config)
        bind, port, allowed_hosts, cert_path, key_path, resource, authorization_servers = validate_transport_config(config)
        if args.check_config:
            print(f"valid transport configuration for {bind}:{port}")
            return 0
        server = LabStewardHTTPServer((bind, port), MCPHandler)
        server.allowed_hosts = allowed_hosts
        server.resource = resource
        server.authorization_servers = authorization_servers
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.options |= ssl.OP_NO_COMPRESSION
        context.load_cert_chain(cert_path, key_path)
        server.ssl_context = context
        audit("service_started", bind=bind, port=port)
        server.serve_forever(poll_interval=0.5)
    except (OSError, ValueError, json.JSONDecodeError, ssl.SSLError) as exc:
        audit("service_start_failed", reason=type(exc).__name__)
        return 1
    except KeyboardInterrupt:
        return 0
    finally:
        if "server" in locals():
            server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
