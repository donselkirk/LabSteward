#!/usr/bin/env python3
"""OAuth authorization server and browser admin interface for LabSteward."""

from __future__ import annotations

import argparse
import base64
import collections
import hashlib
import hmac
import html
import ipaddress
import json
import os
import re
import secrets
import socket
import ssl
import tempfile
import threading
import time
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlencode, urlsplit, urlunsplit

DEFAULT_CONFIG = Path(
    os.environ.get("LABSTEWARD_ADMIN_CONFIG", "/etc/labsteward-admin/config.json")
)
ADMIN_CREDENTIAL = Path(
    os.environ.get("LABSTEWARD_ADMIN_CREDENTIAL", "/etc/labsteward-admin/admin.json")
)
OAUTH_STATE = Path(
    os.environ.get("LABSTEWARD_OAUTH_STATE", "/var/lib/labsteward-admin/oauth.json")
)
BROKER_SOCKET = Path(
    os.environ.get("LABSTEWARD_BROKER_SOCKET", "/run/labsteward/admin-broker.sock")
)

MAX_BODY_BYTES = 64 * 1024
MAX_JSON_BYTES = 1024 * 1024
ACCESS_TOKEN_SECONDS = 10 * 60
REFRESH_TOKEN_SECONDS = 30 * 24 * 60 * 60
AUTH_CODE_SECONDS = 2 * 60
TRANSACTION_SECONDS = 10 * 60
SESSION_IDLE_SECONDS = 15 * 60
MAX_STATE_ITEMS = 2048
IDENTIFIER = re.compile(r"^[a-z][a-z0-9-]{0,31}$")
TOKEN_VALUE = re.compile(r"^ls[acr]_[A-Za-z0-9_-]{43}$")


class AdminError(Exception):
    """A safe request error."""


def read_object(path: Path) -> dict[str, Any]:
    try:
        if path.stat().st_size > MAX_JSON_BYTES:
            raise AdminError("Stored authorization data exceeds the size limit")
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise AdminError("Required authorization data is unavailable") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise AdminError("Stored authorization data is invalid") from exc
    if not isinstance(value, dict):
        raise AdminError("Stored authorization data is invalid")
    return value


def atomic_write(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(value, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        if path.exists():
            metadata = path.stat()
            os.chown(temporary, metadata.st_uid, metadata.st_gid)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def empty_oauth_state() -> dict[str, Any]:
    return {
        "schema": 1,
        "registrations": {},
        "transactions": {},
        "codes": {},
        "refresh_tokens": {},
    }


def clean_state(state: dict[str, Any]) -> dict[str, Any]:
    now = int(time.time())
    for name in ("transactions", "codes", "refresh_tokens"):
        registry = state.get(name)
        if not isinstance(registry, dict):
            raise AdminError("OAuth state is inconsistent")
        state[name] = {
            key: item
            for key, item in registry.items()
            if isinstance(item, dict) and isinstance(item.get("expires_at"), int) and item["expires_at"] > now
        }
    if not isinstance(state.get("registrations"), dict):
        raise AdminError("OAuth state is inconsistent")
    return state


def token_digest(value: str) -> str:
    return hashlib.sha256(value.encode("ascii")).hexdigest()


def b64url_sha256(value: str) -> str:
    digest = hashlib.sha256(value.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def redirect_with_query(url: str, values: dict[str, str]) -> str:
    parsed = urlsplit(url)
    query = "&".join(item for item in (parsed.query, urlencode(values)) if item)
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, query, ""))


def normalize_source(value: str) -> str:
    address = ipaddress.ip_address(value)
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        return str(address.ipv4_mapped)
    return str(address)


def source_allowed(source: str, networks: object) -> bool:
    if not isinstance(networks, list):
        return False
    try:
        address = ipaddress.ip_address(source)
    except ValueError:
        return False
    for value in networks:
        try:
            network = ipaddress.ip_network(value, strict=False)
        except (TypeError, ValueError):
            continue
        if address.version == network.version and address in network:
            return True
    return False


def require_loopback_redirect(value: object) -> str:
    if not isinstance(value, str) or len(value) > 2048:
        raise AdminError("Invalid redirect URI")
    parsed = urlsplit(value)
    if parsed.scheme != "http" or parsed.fragment or parsed.username or parsed.password:
        raise AdminError("OAuth redirect URIs must be loopback HTTP URLs")
    try:
        address = ipaddress.ip_address(parsed.hostname or "")
        redirect_port = parsed.port
    except ValueError as exc:
        raise AdminError("OAuth redirect URIs must use a loopback IP literal") from exc
    if not address.is_loopback or redirect_port is None or not parsed.path.startswith("/"):
        raise AdminError("OAuth redirect URIs must use a loopback IP, port, and path")
    return value


def read_admin_credential() -> dict[str, Any]:
    value = read_object(ADMIN_CREDENTIAL)
    if value.get("schema") != 1 or value.get("algorithm") != "scrypt":
        raise AdminError("Administrator credentials are not initialized")
    return value


def password_matches(username: str, password: str) -> bool:
    try:
        record = read_admin_credential()
        salt = base64.b64decode(record["salt"], validate=True)
        expected = base64.b64decode(record["digest"], validate=True)
        candidate = hashlib.scrypt(
            password.encode("utf-8"),
            salt=salt,
            n=int(record["n"]),
            r=int(record["r"]),
            p=int(record["p"]),
            dklen=len(expected),
            maxmem=64 * 1024 * 1024,
        )
        name_matches = hmac.compare_digest(username, str(record["username"]))
        digest_matches = hmac.compare_digest(candidate, expected)
        return name_matches and digest_matches
    except (AdminError, KeyError, TypeError, ValueError):
        # Perform comparable work even when the record is malformed.
        hashlib.scrypt(password.encode("utf-8"), salt=b"0" * 16, n=2**14, r=8, p=1, dklen=32)
        return False


def broker_call(operation: str, arguments: dict[str, Any] | None = None) -> dict[str, Any]:
    request = json.dumps(
        {"operation": operation, "arguments": arguments or {}}, separators=(",", ":")
    ).encode("utf-8") + b"\n"
    if len(request) > MAX_BODY_BYTES:
        raise AdminError("Management request exceeds the size limit")
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(5)
            connection.connect(str(BROKER_SOCKET))
            connection.sendall(request)
            stream = connection.makefile("rb")
            raw = stream.readline(MAX_BODY_BYTES + 1)
    except OSError as exc:
        raise AdminError("The protected management broker is unavailable") from exc
    if not raw or len(raw) > MAX_BODY_BYTES:
        raise AdminError("The protected management broker returned an invalid response")
    try:
        response = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise AdminError("The protected management broker returned an invalid response") from exc
    if not isinstance(response, dict) or response.get("ok") is not True:
        message = response.get("error") if isinstance(response, dict) else None
        raise AdminError(message if isinstance(message, str) else "Management operation failed")
    result = response.get("result")
    if not isinstance(result, dict):
        raise AdminError("The protected management broker returned an invalid response")
    return result


class SlidingLimiter:
    def __init__(self, maximum: int, window: int) -> None:
        self.maximum = maximum
        self.window = window
        self.entries: dict[str, collections.deque[float]] = {}
        self.lock = threading.Lock()

    def allow(self, source: str) -> bool:
        now = time.monotonic()
        with self.lock:
            history = self.entries.setdefault(source, collections.deque())
            while history and history[0] < now - self.window:
                history.popleft()
            if len(history) >= self.maximum:
                return False
            history.append(now)
            if len(self.entries) > 1024:
                empty = [key for key, value in self.entries.items() if not value]
                for key in empty:
                    self.entries.pop(key, None)
            return True


class AdminServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int], handler: type[BaseHTTPRequestHandler]):
        super().__init__(address, handler)
        self.allowed_hosts: list[str] = []
        self.admin_sources: list[str] = []
        self.enrollment_sources: list[str] = []
        self.issuer = ""
        self.resource = ""
        self.ssl_context: ssl.SSLContext | None = None
        self.state_lock = threading.Lock()
        self.sessions: dict[str, dict[str, Any]] = {}
        self.session_lock = threading.Lock()
        self.request_limiter = SlidingLimiter(120, 60)
        self.login_limiter = SlidingLimiter(5, 300)
        self.connection_slots = threading.BoundedSemaphore(32)

    def process_request(self, request: Any, client_address: tuple[str, int]) -> None:
        if not self.connection_slots.acquire(blocking=False):
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
            request.settimeout(15)
            if self.ssl_context is None:
                raise ssl.SSLError("TLS context unavailable")
            tls_request = self.ssl_context.wrap_socket(request, server_side=True)
            super().process_request_thread(tls_request, client_address)
        except (OSError, ssl.SSLError):
            try:
                request.close()
            except OSError:
                pass
        finally:
            self.connection_slots.release()

    def load_state(self) -> dict[str, Any]:
        with self.state_lock:
            if not OAUTH_STATE.exists():
                atomic_write(OAUTH_STATE, empty_oauth_state())
            state = read_object(OAUTH_STATE)
            if state.get("schema") != 1:
                raise AdminError("Unsupported OAuth state")
            cleaned = clean_state(state)
            atomic_write(OAUTH_STATE, cleaned)
            return cleaned

    def update_state(self, operation: Any) -> Any:
        with self.state_lock:
            if not OAUTH_STATE.exists():
                atomic_write(OAUTH_STATE, empty_oauth_state())
            state = clean_state(read_object(OAUTH_STATE))
            result = operation(state)
            for name in ("registrations", "transactions", "codes", "refresh_tokens"):
                if len(state.get(name, {})) > MAX_STATE_ITEMS:
                    raise AdminError("OAuth state registry is full")
            atomic_write(OAUTH_STATE, clean_state(state))
            return result


STYLE = """
:root{color-scheme:dark;--bg:#0b1220;--panel:#131d2f;--line:#2a3850;--text:#e9eef7;--muted:#9aabc1;--accent:#6ee7b7;--danger:#fb7185}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:15px system-ui,sans-serif}main{max-width:1100px;margin:0 auto;padding:32px 20px}h1,h2{margin:.2em 0 .7em}h3,h4{margin:.4em 0 .7em}p{line-height:1.5}.muted{color:var(--muted)}
nav,.client-head,.row-actions,.page-tabs{display:flex;justify-content:space-between;align-items:center;gap:10px}nav{margin-bottom:14px}.page-tabs{justify-content:flex-start;margin-bottom:24px;border-bottom:1px solid var(--line)}.page-tabs a{padding:10px 14px;text-decoration:none;color:var(--muted);border-bottom:2px solid transparent}.page-tabs a.active{color:var(--text);border-color:var(--accent)}
.card,section,.client-card{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:18px;margin:14px 0}.client-card{background:#101a2b}.client-settings{display:grid;grid-template-columns:minmax(250px,1fr) auto;gap:14px;align-items:end}.row-actions{justify-content:flex-end;white-space:nowrap}
.server-access{border:1px solid var(--line);border-radius:10px;overflow:hidden;background:#0d1728}.access-row+.access-row{border-top:1px solid var(--line)}.access-row summary{display:grid;grid-template-columns:minmax(180px,1fr) auto auto;gap:14px;align-items:start;padding:13px 14px;cursor:pointer;list-style:none}.access-row summary::-webkit-details-marker{display:none}.collapse-icon{display:inline-block;width:9px;height:9px;border-right:2px solid var(--accent);border-bottom:2px solid var(--accent);transform:rotate(45deg);transition:transform .15s ease;margin:2px 4px 0}.access-row[open] .collapse-icon{transform:rotate(225deg);margin-top:7px}.sr-only{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0}.access-body{border-top:1px solid var(--line);padding:14px}.permission-list{display:grid;gap:0;margin-bottom:14px}.permission-control{display:grid;grid-template-columns:minmax(220px,1fr) auto;align-items:start;gap:16px;padding:10px 0}.permission-control+.permission-control{border-top:1px solid var(--line)}.permission-name{font-weight:600}.permission-description{display:block;color:var(--muted);font-size:13px;margin-top:3px}.help{display:inline-grid;place-items:center;width:17px;height:17px;border:1px solid var(--line);border-radius:50%;font-size:11px;color:var(--muted);cursor:help;margin-left:5px}.level-toggle{display:inline-flex;border:1px solid var(--line);border-radius:7px;overflow:hidden}.level-choice{display:inline-flex;align-items:center;margin:0;padding:7px 11px;background:#111d31;cursor:pointer}.level-choice+.level-choice{border-left:1px solid var(--line)}.level-choice:has(input:checked){background:#1d6f58;color:#fff}.level-choice input{position:absolute;opacity:0;pointer-events:none}
table{width:100%;border-collapse:collapse}th,td{text-align:left;border-bottom:1px solid var(--line);padding:10px 8px;vertical-align:top}input,select,button,.button-link{font:inherit;border-radius:7px;border:1px solid var(--line);padding:8px 10px;background:#0d1728;color:var(--text)}button{cursor:pointer;background:#1d6f58;border-color:#2ca47e}button.secondary{background:#18243a;border-color:var(--line)}button.danger{background:#7f1d32;border-color:#be3453}button:disabled{cursor:not-allowed;opacity:.55}.button-link{display:inline-block;text-decoration:none;background:#18243a}form.inline{display:inline-flex;gap:8px;flex-wrap:wrap}.notice{border-left:4px solid var(--accent);padding:10px 14px;background:#10251f}.error{border-left-color:var(--danger);background:#2b1118}.pill{display:inline-block;border:1px solid var(--line);border-radius:999px;padding:3px 8px;margin:2px}.login{max-width:430px;margin:10vh auto}label{display:block;margin:12px 0 5px}a{color:var(--accent)}
@media(max-width:720px){.client-head{align-items:flex-start;flex-direction:column}.client-settings{grid-template-columns:1fr}.access-row summary{grid-template-columns:1fr}.permission-control{grid-template-columns:1fr}.row-actions{justify-content:flex-start;white-space:normal}.page-tabs{overflow-x:auto}table{display:block;overflow-x:auto}}
""".strip()


class AdminHandler(BaseHTTPRequestHandler):
    server_version = "LabSteward"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    def log_message(self, _format: str, *_args: object) -> None:
        return

    @property
    def source(self) -> str:
        try:
            return normalize_source(self.client_address[0])
        except ValueError:
            return "invalid"

    def host_allowed(self) -> bool:
        header = self.headers.get("Host", "")
        if header.startswith("["):
            host = header[1:].split("]", 1)[0]
        else:
            host = header.rsplit(":", 1)[0]
        return host.lower().rstrip(".") in self.server.allowed_hosts  # type: ignore[attr-defined]

    def security_headers(self, content_type: str) -> None:
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'none'; style-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
        )

    def send_bytes(self, status: int, body: bytes, content_type: str) -> None:
        self.close_connection = True
        self.send_response(status)
        self.security_headers(content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def send_json(self, status: int, payload: dict[str, Any]) -> None:
        self.send_bytes(
            status,
            json.dumps(payload, separators=(",", ":"), ensure_ascii=True).encode("utf-8"),
            "application/json",
        )

    def send_html(self, status: int, title: str, content: str) -> None:
        page = (
            "<!doctype html><html lang=en><head><meta charset=utf-8>"
            "<meta name=viewport content='width=device-width,initial-scale=1'>"
            f"<title>{html.escape(title)} · LabSteward</title>"
            "<link rel=stylesheet href=/admin/style.css></head><body><main>"
            f"{content}</main></body></html>"
        )
        self.send_bytes(status, page.encode("utf-8"), "text/html; charset=utf-8")

    def redirect(self, location: str, *, cookie: str | None = None) -> None:
        self.close_connection = True
        self.send_response(303)
        self.security_headers("text/plain; charset=utf-8")
        self.send_header("Location", location)
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.send_header("Content-Length", "0")
        self.send_header("Connection", "close")
        self.end_headers()

    def read_body(self) -> bytes:
        if self.headers.get("Transfer-Encoding") is not None:
            raise AdminError("Chunked request bodies are not accepted")
        values = self.headers.get_all("Content-Length", [])
        if len(values) != 1:
            raise AdminError("A single Content-Length header is required")
        try:
            length = int(values[0])
        except ValueError as exc:
            raise AdminError("Invalid Content-Length") from exc
        if length < 0 or length > MAX_BODY_BYTES:
            raise AdminError("Request body exceeds the size limit")
        return self.rfile.read(length)

    def read_form(self) -> dict[str, str]:
        if self.headers.get("Content-Type", "").split(";", 1)[0].lower() != "application/x-www-form-urlencoded":
            raise AdminError("Expected a form request")
        try:
            values = parse_qs(self.read_body().decode("utf-8"), keep_blank_values=True, max_num_fields=128)
        except (UnicodeDecodeError, ValueError) as exc:
            raise AdminError("Invalid form request") from exc
        return {key: items[-1] for key, items in values.items() if items}

    def read_json_body(self) -> dict[str, Any]:
        if self.headers.get("Content-Type", "").split(";", 1)[0].lower() != "application/json":
            raise AdminError("Expected a JSON request")
        try:
            value = json.loads(self.read_body())
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise AdminError("Invalid JSON request") from exc
        if not isinstance(value, dict):
            raise AdminError("Expected a JSON object")
        return value

    def origin_allowed(self) -> bool:
        return self.headers.get("Origin") == self.server.issuer  # type: ignore[attr-defined]

    def session(self) -> tuple[str, dict[str, Any]] | None:
        raw = self.headers.get("Cookie")
        if not raw:
            return None
        jar = cookies.SimpleCookie()
        try:
            jar.load(raw)
        except cookies.CookieError:
            return None
        morsel = jar.get("labsteward_admin")
        if morsel is None:
            return None
        session_id = morsel.value
        if not re.fullmatch(r"[A-Za-z0-9_-]{43}", session_id):
            return None
        now = int(time.time())
        with self.server.session_lock:  # type: ignore[attr-defined]
            session = self.server.sessions.get(token_digest(session_id))  # type: ignore[attr-defined]
            if (
                not isinstance(session, dict)
                or session.get("source") != self.source
                or session.get("last_seen", 0) + SESSION_IDLE_SECONDS <= now
            ):
                return None
            session["last_seen"] = now
            return session_id, dict(session)

    def require_session(self, csrf: str | None = None) -> tuple[str, dict[str, Any]]:
        session = self.session()
        if session is None:
            raise AdminError("Administrator authentication is required")
        if csrf is not None and not hmac.compare_digest(str(session[1].get("csrf", "")), csrf):
            raise AdminError("Invalid form security token")
        return session

    def require_admin_source(self) -> None:
        if not source_allowed(self.source, self.server.admin_sources):  # type: ignore[attr-defined]
            raise AdminError("Administrator access is not allowed from this source")

    def require_enrollment_source(self) -> None:
        if not source_allowed(self.source, self.server.enrollment_sources):  # type: ignore[attr-defined]
            raise AdminError("Client enrollment is not allowed from this source")

    def browser_error(self, message: str, status: int = 400) -> None:
        self.send_html(
            status,
            "Request denied",
            f"<section class='notice error'><h1>Request denied</h1><p>{html.escape(message)}</p></section>",
        )

    def do_GET(self) -> None:  # noqa: N802
        if not self.server.request_limiter.allow(self.source):  # type: ignore[attr-defined]
            self.send_json(429, {"error": "rate_limited"})
            return
        if not self.host_allowed():
            self.send_json(403, {"error": "invalid_host"})
            return
        path = urlsplit(self.path).path
        try:
            if path == "/.well-known/oauth-authorization-server":
                self.oauth_metadata()
            elif path == "/admin/style.css":
                self.send_bytes(200, STYLE.encode("utf-8"), "text/css; charset=utf-8")
            elif path == "/admin/login":
                self.require_admin_source()
                self.login_page()
            elif path in {"/admin", "/admin/servers", "/admin/plugins"}:
                self.require_admin_source()
                if self.session() is None:
                    self.redirect("/admin/login")
                else:
                    page = {"/admin": "clients", "/admin/servers": "servers", "/admin/plugins": "plugins"}[path]
                    query = parse_qs(urlsplit(self.path).query, keep_blank_values=True, max_num_fields=8)
                    self.dashboard(page=page, selected_server=query.get("server", [""])[-1])
            elif path == "/authorize":
                self.require_enrollment_source()
                self.authorize_page()
            else:
                self.send_json(404, {"error": "not_found"})
        except AdminError as exc:
            self.browser_error(str(exc), 403 if "not allowed" in str(exc) else 400)

    def do_POST(self) -> None:  # noqa: N802
        if not self.server.request_limiter.allow(self.source):  # type: ignore[attr-defined]
            self.send_json(429, {"error": "rate_limited"})
            return
        if not self.host_allowed():
            self.send_json(403, {"error": "invalid_host"})
            return
        path = urlsplit(self.path).path
        try:
            if path == "/oauth/register":
                self.require_enrollment_source()
                self.oauth_register()
            elif path == "/oauth/token":
                self.require_enrollment_source()
                self.oauth_token()
            elif path == "/oauth/revoke":
                self.require_enrollment_source()
                self.oauth_revoke()
            elif path == "/admin/login":
                self.require_admin_source()
                self.login()
            elif path == "/admin/logout":
                self.require_admin_source()
                form = self.read_form()
                session_id, _session = self.require_session(form.get("csrf"))
                with self.server.session_lock:  # type: ignore[attr-defined]
                    self.server.sessions.pop(token_digest(session_id), None)  # type: ignore[attr-defined]
                self.redirect(
                    "/admin/login",
                    cookie="labsteward_admin=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0",
                )
            elif path == "/authorize":
                self.require_enrollment_source()
                self.authorize_decision()
            elif path.startswith("/admin/"):
                self.require_admin_source()
                if not self.origin_allowed():
                    raise AdminError("Invalid browser origin")
                self.admin_operation(path)
            else:
                self.send_json(404, {"error": "not_found"})
        except AdminError as exc:
            if path.startswith("/oauth/"):
                self.send_json(400, {"error": "invalid_request", "error_description": str(exc)})
            else:
                self.browser_error(str(exc), 403 if "not allowed" in str(exc) else 400)

    def oauth_metadata(self) -> None:
        issuer = self.server.issuer  # type: ignore[attr-defined]
        self.send_json(
            200,
            {
                "issuer": issuer,
                "authorization_endpoint": f"{issuer}/authorize",
                "token_endpoint": f"{issuer}/oauth/token",
                "registration_endpoint": f"{issuer}/oauth/register",
                "revocation_endpoint": f"{issuer}/oauth/revoke",
                "response_types_supported": ["code"],
                "grant_types_supported": ["authorization_code", "refresh_token"],
                "code_challenge_methods_supported": ["S256"],
                "token_endpoint_auth_methods_supported": ["none"],
                "scopes_supported": ["mcp:connect"],
            },
        )

    def login_page(self, error: str = "", transaction: str = "") -> None:
        error_html = f"<p class='notice error'>{html.escape(error)}</p>" if error else ""
        transaction_field = (
            f"<input type=hidden name=transaction value='{html.escape(transaction)}'>"
            if transaction
            else ""
        )
        self.send_html(
            200,
            "Administrator sign in",
            "<section class=login><h1>LabSteward</h1><p class=muted>Administrator sign in</p>"
            f"{error_html}<form method=post action=/admin/login>{transaction_field}"
            "<label for=username>Username</label><input id=username name=username required autocomplete=username>"
            "<label for=password>Password</label><input id=password name=password type=password required autocomplete=current-password>"
            "<p><button type=submit>Sign in</button></p></form></section>",
        )

    def login(self) -> None:
        if not self.origin_allowed():
            raise AdminError("Invalid browser origin")
        form = self.read_form()
        transaction = form.get("transaction", "")
        if not self.server.login_limiter.allow(self.source):  # type: ignore[attr-defined]
            self.login_page("Too many sign-in attempts. Try again later.", transaction)
            return
        if not password_matches(form.get("username", ""), form.get("password", "")):
            time.sleep(0.25)
            self.login_page("Sign-in failed.", transaction)
            return
        now = int(time.time())
        session_id = secrets.token_urlsafe(32)
        with self.server.session_lock:  # type: ignore[attr-defined]
            self.server.sessions = {  # type: ignore[attr-defined]
                key: value
                for key, value in self.server.sessions.items()  # type: ignore[attr-defined]
                if isinstance(value, dict) and value.get("last_seen", 0) + SESSION_IDLE_SECONDS > now
            }
            if len(self.server.sessions) >= 1024:  # type: ignore[attr-defined]
                oldest = min(
                    self.server.sessions,  # type: ignore[attr-defined]
                    key=lambda key: self.server.sessions[key].get("last_seen", 0),  # type: ignore[attr-defined]
                )
                self.server.sessions.pop(oldest, None)  # type: ignore[attr-defined]
            self.server.sessions[token_digest(session_id)] = {  # type: ignore[attr-defined]
                "source": self.source,
                "csrf": secrets.token_urlsafe(32),
                "last_seen": now,
            }
        destination = f"/authorize?transaction={urlencode({'x': transaction})[2:]}" if transaction else "/admin"
        self.redirect(
            destination,
            cookie=(
                f"labsteward_admin={session_id}; Path=/; Secure; HttpOnly; SameSite=Strict; "
                f"Max-Age={SESSION_IDLE_SECONDS}"
            ),
        )

    def dashboard(
        self, notice: str = "", page: str = "clients", selected_server: str = ""
    ) -> None:
        """Render the focused Clients, Servers, or Plugins administration page."""
        _session_id, session = self.require_session()
        state = broker_call("state.get")
        csrf = html.escape(str(session["csrf"]))
        notice_html = f"<p class=notice>{html.escape(notice)}</p>" if notice else ""
        clients = {
            client_id: client
            for client_id, client in state.get("clients", {}).items()
            if isinstance(client, dict) and client.get("enabled") is True
        }
        servers = state.get("servers", {})
        installed = state.get("plugins", {})
        catalog_by_id = {
            str(item.get("id")): item
            for item in state.get("catalog", [])
            if isinstance(item, dict)
        }

        def level_mapping(value: object) -> dict[str, str]:
            if isinstance(value, list):
                return {str(item): "read" for item in value}
            if isinstance(value, dict):
                return {str(key): str(level) for key, level in value.items()}
            return {}

        def permission_names(plugin_id: str) -> list[str]:
            raw = catalog_by_id.get(plugin_id, {}).get("permissions", {})
            values = raw if isinstance(raw, list) else raw.keys() if isinstance(raw, dict) else []
            return sorted(str(item) for item in values)

        def permission_controls(plugin_id: str, selected: object, form_id: str) -> str:
            active = level_mapping(selected)
            raw_descriptions = catalog_by_id.get(plugin_id, {}).get(
                "permission_descriptions", {}
            )
            descriptions = raw_descriptions if isinstance(raw_descriptions, dict) else {}
            controls = []
            for permission in permission_names(plugin_id):
                description = str(
                    descriptions.get(permission, "Plugin-defined capability.")
                )
                choices = "".join(
                    "<label class=level-choice>"
                    f"<input type=radio name='permission.{html.escape(permission)}' value='{level}'"
                    f" aria-label='{html.escape(permission)} {level}'"
                    f" {'checked' if active.get(permission, 'off') == level else ''}"
                    f" form='{html.escape(form_id)}'><span>{level.title()}</span></label>"
                    for level in ("off", "read", "write")
                )
                controls.append(
                    "<div class=permission-control><div>"
                    f"<span class=permission-name>{html.escape(permission)}</span>"
                    f"<span class=help title='{html.escape(description)}' aria-label='{html.escape(description)}'>?</span>"
                    f"<span class=permission-description>{html.escape(description)}</span>"
                    f"</div><span class=level-toggle>{choices}</span></div>"
                )
            return "".join(controls) or "<span class=muted>No permissions are declared by this plugin.</span>"

        navigation = (
            "<nav><div><h1>LabSteward</h1><span class=muted>Administration</span></div>"
            "<form method=post action=/admin/logout>"
            f"<input type=hidden name=csrf value='{csrf}'><button type=submit>Sign out</button></form></nav>"
            "<div class=page-tabs>"
            f"<a href=/admin class='{'active' if page == 'clients' else ''}'>Clients</a>"
            f"<a href=/admin/servers class='{'active' if page == 'servers' else ''}'>Servers</a>"
            f"<a href=/admin/plugins class='{'active' if page == 'plugins' else ''}'>Plugins</a></div>"
        )

        if page == "clients":
            client_cards = []
            for client_id, client in sorted(clients.items()):
                sources = ", ".join(client.get("sources", []))
                grants = client.get("grants", {}) if isinstance(client.get("grants"), dict) else {}
                source_form_id = f"client-sources-{client_id}"
                access_rows = []
                for alias, granted in sorted(grants.items()):
                    server = servers.get(alias)
                    if not isinstance(server, dict):
                        continue
                    plugin_id = str(server.get("plugin", ""))
                    form_id = f"client-grants-{client_id}-{alias}"
                    configured_count = len(level_mapping(granted))
                    controls = permission_controls(plugin_id, granted, form_id)
                    access_rows.append(
                        "<details class=access-row><summary>"
                        f"<span><strong>{html.escape(alias)}</strong><br><span class=muted>{html.escape(plugin_id)}</span></span>"
                        f"<span class=muted>{configured_count} permission(s)</span><span><span class=sr-only>Toggle server permissions</span><span class=collapse-icon aria-hidden=true></span></span></summary>"
                        "<div class=access-body>"
                        f"<form id='{html.escape(form_id)}' method=post action=/admin/client/grants>"
                        f"<input type=hidden name=csrf value='{csrf}'><input type=hidden name=client value='{html.escape(client_id)}'>"
                        f"<input type=hidden name=server value='{html.escape(alias)}'><div class=permission-list>{controls}</div></form>"
                        "<div class=row-actions>"
                        f"<button type=submit form='{html.escape(form_id)}'>Save</button>"
                        "<form class=inline method=post action=/admin/client/server/remove>"
                        f"<input type=hidden name=csrf value='{csrf}'><input type=hidden name=client value='{html.escape(client_id)}'>"
                        f"<input type=hidden name=server value='{html.escape(alias)}'>"
                        "<button class=danger type=submit>Remove server</button></form></div></div></details>"
                    )
                access_content = (
                    "<div class=server-access>" + "".join(access_rows) + "</div>"
                    if access_rows
                    else "<p class=muted>No servers have been added to this client.</p>"
                )
                unassigned = [alias for alias in sorted(servers) if alias not in grants]
                server_options = "".join(
                    f"<option value='{html.escape(alias)}'>{html.escape(alias)} — {html.escape(str(servers[alias].get('plugin','')))}</option>"
                    for alias in unassigned
                )
                add_server = (
                    "<form class=inline method=post action=/admin/client/server/add>"
                    f"<input type=hidden name=csrf value='{csrf}'><input type=hidden name=client value='{html.escape(client_id)}'>"
                    f"<select name=server aria-label='Server to add' required>{server_options or '<option value="">No more servers available</option>'}</select>"
                    f"<button type=submit {'disabled' if not server_options else ''}>Add server</button></form>"
                )
                client_cards.append(
                    "<div class=client-card><div class=client-head><div>"
                    f"<h3>{html.escape(str(client.get('display_name', client_id)))}</h3>"
                    f"<span class=muted>{html.escape(client_id)} · {html.escape(str(client.get('auth','legacy_token')))}</span>"
                    "</div><span class=pill>Enabled</span></div>"
                    "<div class=client-settings><div><h4>Allowed sources</h4>"
                    f"<form id='{html.escape(source_form_id)}' class=inline method=post action=/admin/client/sources>"
                    f"<input type=hidden name=csrf value='{csrf}'><input type=hidden name=client value='{html.escape(client_id)}'>"
                    f"<input name=sources value='{html.escape(sources)}' aria-label='Allowed source CIDRs'></form></div>"
                    f"<div class=row-actions><span class=muted>{len(grants)} server(s)</span>"
                    f"<button type=submit form='{html.escape(source_form_id)}'>Save</button>"
                    "<form class=inline method=post action=/admin/client/revoke>"
                    f"<input type=hidden name=csrf value='{csrf}'><input type=hidden name=client value='{html.escape(client_id)}'>"
                    "<button class=danger type=submit>Revoke &amp; remove</button></form></div></div>"
                    f"<h4>Server access</h4>{access_content}<h4>Add server</h4>{add_server}</div>"
                )
            content = (
                "<section><h2>Clients</h2><p class=muted>Manage source restrictions and explicitly assigned servers. Expand a server only when you need to change its permissions.</p>"
                + ("".join(client_cards) or "<p>No clients</p>") + "</section>"
            )
        elif page == "servers":
            plugin_options = "".join(
                f"<option value='{html.escape(plugin_id)}'>{html.escape(plugin_id)}</option>"
                for plugin_id, record in sorted(installed.items())
                if isinstance(record, dict) and record.get("enabled") is True and plugin_id in catalog_by_id
            )
            server_rows = []
            for alias, server in sorted(servers.items()):
                server_rows.append(
                    f"<tr><td><strong>{html.escape(alias)}</strong></td><td>{html.escape(str(server.get('plugin','')))}</td>"
                    f"<td>{html.escape(str(server.get('endpoint','')))}</td><td><div class=row-actions>"
                    f"<a class=button-link href='/admin/servers?server={html.escape(alias)}'>Configure access</a>"
                    "<form class=inline method=post action=/admin/server/remove>"
                    f"<input type=hidden name=csrf value='{csrf}'><input type=hidden name=server value='{html.escape(alias)}'>"
                    "<button class=danger type=submit>Remove</button></form></div></td></tr>"
                )
            configuration = ""
            if selected_server in servers:
                selected = servers[selected_server]
                configuration = (
                    f"<section><h2>Configure {html.escape(selected_server)} access</h2>"
                    f"<p class=muted>{html.escape(str(selected.get('plugin','')))} at {html.escape(str(selected.get('endpoint','')))}</p>"
                    "<p class=notice>This plugin has not released its write-only credential fields yet. Access setup will appear here with the reviewed plugin credential schema.</p></section>"
                )
            content = (
                "<section><h2>Servers</h2><p class=muted>Register each server once. Removing it automatically removes it from every client.</p>"
                "<table><thead><tr><th>Server</th><th>Plugin</th><th>Endpoint</th><th>Actions</th></tr></thead><tbody>"
                + ("".join(server_rows) or "<tr><td colspan=4>No servers</td></tr>")
                + "</tbody></table><h3>Add server</h3><form class=inline method=post action=/admin/server/add>"
                f"<input type=hidden name=csrf value='{csrf}'><input name=server placeholder='server-name' required>"
                f"<select name=plugin required>{plugin_options or '<option value="">No installed plugins</option>'}</select>"
                "<input name=endpoint type=url placeholder='https://server.example:443' required>"
                f"<button type=submit {'disabled' if not plugin_options else ''}>Add</button></form></section>{configuration}"
            )
        elif page == "plugins":
            plugin_rows = []
            for plugin_id, plugin in sorted(catalog_by_id.items()):
                status = (
                    f"installed {installed[plugin_id].get('version','')}"
                    if plugin_id in installed
                    else str(plugin.get("status", "unavailable"))
                )
                raw_descriptions = plugin.get("permission_descriptions", {})
                descriptions = raw_descriptions if isinstance(raw_descriptions, dict) else {}
                permissions = "".join(
                    f"<span class=pill title='{html.escape(str(descriptions.get(name, 'Plugin-defined capability.')))}'>{html.escape(name)}</span>"
                    for name in permission_names(plugin_id)
                ) or "<span class=muted>None released</span>"
                plugin_rows.append(
                    f"<tr><td>{html.escape(str(plugin.get('name', plugin_id)))}</td><td>{html.escape(status)}</td><td>{permissions}</td></tr>"
                )
            content = (
                "<section><h2>Plugins</h2><p class=muted>Plugins define available capabilities and their descriptions.</p>"
                "<table><thead><tr><th>Plugin</th><th>Status</th><th>Permissions</th></tr></thead><tbody>"
                + ("".join(plugin_rows) or "<tr><td colspan=3>No catalogue entries</td></tr>")
                + "</tbody></table></section>"
            )
        else:
            raise AdminError("Unknown administration page")
        self.send_html(200, f"LabSteward {page.title()}", navigation + notice_html + content)

    def admin_operation(self, path: str) -> None:
        form = self.read_form()
        self.require_session(form.get("csrf"))
        def comma_values(name: str) -> list[str]:
            raw = form.get(name, "")
            values = [item.strip() for item in raw.split(",") if item.strip()]
            if len(values) > 64:
                raise AdminError("Too many values")
            return values
        def selected_permissions() -> dict[str, str]:
            prefix = "permission."
            values = {
                key[len(prefix):]: value
                for key, value in form.items()
                if key.startswith(prefix) and value in {"read", "write"}
            }
            if len(values) > 64:
                raise AdminError("Too many permissions")
            return values
        if path == "/admin/client/revoke":
            broker_call("client.revoke", {"client": form.get("client", "")})
            self.dashboard("Client revoked, removed, and all active OAuth access tokens removed.")
        elif path == "/admin/client/sources":
            broker_call(
                "client.sources",
                {"client": form.get("client", ""), "sources": comma_values("sources")},
            )
            self.dashboard("Client source restrictions updated; active access tokens were revoked.")
        elif path == "/admin/client/server/add":
            broker_call(
                "client.server.add",
                {"client": form.get("client", ""), "server": form.get("server", "")},
            )
            self.dashboard("Server added to client with all permissions off.")
        elif path == "/admin/client/server/remove":
            broker_call(
                "client.server.remove",
                {"client": form.get("client", ""), "server": form.get("server", "")},
            )
            self.dashboard("Server removed from client.")
        elif path == "/admin/client/grants":
            broker_call(
                "client.grants",
                {
                    "client": form.get("client", ""),
                    "server": form.get("server", ""),
                    "permissions": selected_permissions(),
                },
            )
            self.dashboard("Client permissions updated.")
        elif path == "/admin/server/add":
            broker_call(
                "server.add",
                {
                    "server": form.get("server", ""),
                    "plugin": form.get("plugin", ""),
                    "endpoint": form.get("endpoint", ""),
                },
            )
            self.dashboard("Server registered.", page="servers")
        elif path == "/admin/server/remove":
            broker_call("server.remove", {"server": form.get("server", "")})
            self.dashboard(
                "Server removed from every client. Protected credentials were not deleted.",
                page="servers",
            )
        else:
            raise AdminError("Unsupported administration operation")

    def oauth_register(self) -> None:
        payload = self.read_json_body()
        redirect_values = payload.get("redirect_uris")
        if not isinstance(redirect_values, list) or not 1 <= len(redirect_values) <= 8:
            raise AdminError("One to eight redirect URIs are required")
        redirects = [require_loopback_redirect(item) for item in redirect_values]
        methods = payload.get("token_endpoint_auth_method", "none")
        if methods != "none":
            raise AdminError("Only public OAuth clients are supported")
        name = payload.get("client_name", "MCP client")
        if not isinstance(name, str) or not name.strip() or len(name) > 80:
            raise AdminError("Invalid client name")
        client_id = f"lsd_{secrets.token_urlsafe(24)}"
        def register(state: dict[str, Any]) -> None:
            state["registrations"][client_id] = {
                "name": name.strip(),
                "redirect_uris": redirects,
                "created_at": int(time.time()),
            }
        self.server.update_state(register)  # type: ignore[attr-defined]
        self.send_json(
            201,
            {
                "client_id": client_id,
                "client_name": name.strip(),
                "redirect_uris": redirects,
                "token_endpoint_auth_method": "none",
                "grant_types": ["authorization_code", "refresh_token"],
                "response_types": ["code"],
            },
        )

    def validated_authorize(self, query: dict[str, list[str]]) -> dict[str, str]:
        required = (
            "response_type",
            "client_id",
            "redirect_uri",
            "code_challenge",
            "code_challenge_method",
            "state",
            "scope",
            "resource",
        )
        values = {}
        for key in required:
            items = query.get(key, [])
            if len(items) != 1 or not items[0] or len(items[0]) > 2048:
                raise AdminError(f"Invalid OAuth {key}")
            values[key] = items[0]
        if values["response_type"] != "code" or values["code_challenge_method"] != "S256":
            raise AdminError("Only authorization code with PKCE S256 is supported")
        if not re.fullmatch(r"[A-Za-z0-9_-]{43,128}", values["code_challenge"]):
            raise AdminError("Invalid PKCE challenge")
        if values["scope"] != "mcp:connect" or values["resource"] != self.server.resource:  # type: ignore[attr-defined]
            raise AdminError("Invalid OAuth scope or resource")
        state = self.server.load_state()  # type: ignore[attr-defined]
        registration = state["registrations"].get(values["client_id"])
        if not isinstance(registration, dict) or values["redirect_uri"] not in registration.get("redirect_uris", []):
            raise AdminError("Unknown OAuth client or redirect URI")
        values["client_name"] = str(registration.get("name", "MCP client"))
        return values

    def authorize_page(self) -> None:
        query = parse_qs(urlsplit(self.path).query, keep_blank_values=True, max_num_fields=32)
        existing = query.get("transaction", [])
        state = self.server.load_state()  # type: ignore[attr-defined]
        if len(existing) == 1:
            transaction_id = existing[0]
            transaction = state["transactions"].get(token_digest(transaction_id))
            if not isinstance(transaction, dict) or transaction.get("source") != self.source:
                raise AdminError("Enrollment request expired")
        else:
            values = self.validated_authorize(query)
            transaction_id = secrets.token_urlsafe(32)
            transaction = {**values, "source": self.source, "expires_at": int(time.time()) + TRANSACTION_SECONDS}
            def save_transaction(current: dict[str, Any]) -> None:
                current["transactions"][token_digest(transaction_id)] = transaction
            self.server.update_state(save_transaction)  # type: ignore[attr-defined]
        session = self.session()
        if session is None:
            self.login_page(transaction=transaction_id)
            return
        csrf = html.escape(str(session[1]["csrf"]))
        suggested = re.sub(r"[^a-z0-9-]+", "-", str(transaction["client_name"]).lower()).strip("-")
        if not IDENTIFIER.fullmatch(suggested):
            suggested = "mcp-client"
        source = ipaddress.ip_address(self.source)
        source_cidr = f"{source}/{32 if source.version == 4 else 128}"
        self.send_html(
            200,
            "Trust client",
            "<section class=login><h1>Trust this MCP client?</h1>"
            f"<p><strong>{html.escape(str(transaction['client_name']))}</strong> is requesting access to LabSteward.</p>"
            "<p class=notice>Approval grants only the sanitized built-in health check. It does not grant access to any server or plugin.</p>"
            f"<p>Observed source: <code>{html.escape(self.source)}</code><br>Callback: <code>{html.escape(str(transaction['redirect_uri']))}</code></p>"
            "<form method=post action=/authorize>"
            f"<input type=hidden name=csrf value='{csrf}'><input type=hidden name=transaction value='{html.escape(transaction_id)}'>"
            f"<label for=client>Client name</label><input id=client name=client value='{html.escape(suggested)}' required pattern='[a-z][a-z0-9-]{{0,31}}'>"
            f"<label for=source>Allowed source</label><input id=source name=source value='{html.escape(source_cidr)}' required>"
            "<p><button type=submit name=decision value=approve>Trust client</button> "
            "<button class=danger type=submit name=decision value=deny>Deny</button></p></form></section>",
        )

    def authorize_decision(self) -> None:
        if not self.origin_allowed():
            raise AdminError("Invalid browser origin")
        form = self.read_form()
        self.require_session(form.get("csrf"))
        transaction_id = form.get("transaction", "")
        decision = form.get("decision")
        client_id = form.get("client", "")
        source = form.get("source", "")
        def decide(state: dict[str, Any]) -> tuple[dict[str, Any], str | None]:
            transaction = state["transactions"].pop(token_digest(transaction_id), None)
            if not isinstance(transaction, dict) or transaction.get("source") != self.source:
                raise AdminError("Enrollment request expired")
            if decision != "approve":
                return transaction, None
            if not IDENTIFIER.fullmatch(client_id):
                raise AdminError("Invalid client name")
            approved = broker_call(
                "client.approve",
                {
                    "client": client_id,
                    "display_name": transaction["client_name"],
                    "source": source,
                    "oauth_client_id": transaction["client_id"],
                },
            )
            code_value = f"lsc_{secrets.token_urlsafe(32)}"
            state["codes"][token_digest(code_value)] = {
                "client_id": transaction["client_id"],
                "device_id": client_id,
                "redirect_uri": transaction["redirect_uri"],
                "challenge": transaction["code_challenge"],
                "scope": "mcp:connect",
                "resource": self.server.resource,  # type: ignore[attr-defined]
                "auth_generation": approved["auth_generation"],
                "expires_at": int(time.time()) + AUTH_CODE_SECONDS,
            }
            return transaction, code_value
        transaction, code = self.server.update_state(decide)  # type: ignore[attr-defined]
        redirect_uri = str(transaction["redirect_uri"])
        response_state = str(transaction["state"])
        if code is None:
            self.redirect(redirect_with_query(redirect_uri, {"error": "access_denied", "state": response_state}))
            return
        self.redirect(redirect_with_query(redirect_uri, {"code": code, "state": response_state}))

    def oauth_form(self) -> dict[str, str]:
        return self.read_form()

    def issue_tokens(
        self, state: dict[str, Any], client_id: str, device_id: str, auth_generation: int
    ) -> dict[str, Any]:
        access = f"lsa_{secrets.token_urlsafe(32)}"
        refresh = f"lsr_{secrets.token_urlsafe(32)}"
        now = int(time.time())
        broker_call(
            "token.put",
            {
                "digest": token_digest(access), "client": device_id,
                "expires_at": now + ACCESS_TOKEN_SECONDS,
                "auth_generation": auth_generation,
            },
        )
        state["refresh_tokens"][token_digest(refresh)] = {
            "client_id": client_id,
            "device_id": device_id,
            "auth_generation": auth_generation,
            "expires_at": now + REFRESH_TOKEN_SECONDS,
        }
        return {
            "access_token": access,
            "token_type": "Bearer",
            "expires_in": ACCESS_TOKEN_SECONDS,
            "refresh_token": refresh,
            "scope": "mcp:connect",
        }

    def oauth_token(self) -> None:
        form = self.oauth_form()
        grant_type = form.get("grant_type")
        client_id = form.get("client_id", "")
        def exchange(state: dict[str, Any]) -> dict[str, Any]:
            if client_id not in state["registrations"]:
                raise AdminError("Unknown OAuth client")
            if grant_type == "authorization_code":
                code = form.get("code", "")
                record = state["codes"].pop(token_digest(code), None) if TOKEN_VALUE.fullmatch(code) else None
                if not isinstance(record, dict):
                    raise AdminError("Invalid or expired authorization code")
                if record.get("client_id") != client_id or record.get("redirect_uri") != form.get("redirect_uri"):
                    raise AdminError("Authorization code binding mismatch")
                verifier = form.get("code_verifier", "")
                if not re.fullmatch(r"[A-Za-z0-9._~-]{43,128}", verifier) or not hmac.compare_digest(
                    b64url_sha256(verifier), str(record.get("challenge", ""))
                ):
                    raise AdminError("PKCE verification failed")
                if not isinstance(record.get("auth_generation"), int):
                    raise AdminError("Authorization code metadata is invalid")
                return self.issue_tokens(
                    state, client_id, str(record["device_id"]), record["auth_generation"]
                )
            if grant_type == "refresh_token":
                refresh = form.get("refresh_token", "")
                record = (
                    state["refresh_tokens"].pop(token_digest(refresh), None)
                    if TOKEN_VALUE.fullmatch(refresh)
                    else None
                )
                if not isinstance(record, dict) or record.get("client_id") != client_id:
                    raise AdminError("Invalid or expired refresh token")
                if not isinstance(record.get("auth_generation"), int):
                    raise AdminError("Refresh token metadata is invalid")
                return self.issue_tokens(
                    state, client_id, str(record["device_id"]), record["auth_generation"]
                )
            raise AdminError("Unsupported OAuth grant type")
        payload = self.server.update_state(exchange)  # type: ignore[attr-defined]
        self.send_json(200, payload)

    def oauth_revoke(self) -> None:
        form = self.oauth_form()
        value = form.get("token", "")
        if not TOKEN_VALUE.fullmatch(value):
            self.send_bytes(200, b"", "application/json")
            return
        digest = token_digest(value)
        def revoke(state: dict[str, Any]) -> None:
            state["refresh_tokens"].pop(digest, None)
        self.server.update_state(revoke)  # type: ignore[attr-defined]
        broker_call("token.revoke", {"digest": digest})
        self.send_bytes(200, b"", "application/json")


def validate_config(config: dict[str, Any]) -> dict[str, Any]:
    if config.get("schema") != 1:
        raise AdminError("Unsupported admin configuration")
    bind = str(ipaddress.ip_address(config.get("bind")))
    port = config.get("port")
    if not isinstance(port, int) or not 1024 <= port <= 65535:
        raise AdminError("Invalid admin port")
    allowed_hosts = config.get("allowed_hosts")
    if not isinstance(allowed_hosts, list) or not allowed_hosts or len(allowed_hosts) > 16:
        raise AdminError("Invalid admin Host allowlist")
    normalized_hosts = []
    for host in allowed_hosts:
        if not isinstance(host, str) or not host or len(host) > 253:
            raise AdminError("Invalid admin Host allowlist")
        normalized_hosts.append(host.lower().rstrip("."))
    for name in ("admin_sources", "enrollment_sources"):
        networks = config.get(name)
        if not isinstance(networks, list) or not networks or len(networks) > 16:
            raise AdminError(f"Invalid {name}")
        for network in networks:
            parsed = ipaddress.ip_network(network, strict=False)
            if parsed.prefixlen == 0 or parsed.is_multicast or parsed.is_unspecified:
                raise AdminError(f"Invalid {name}")
    issuer = config.get("issuer")
    resource = config.get("resource")
    for label, value in (("issuer", issuer), ("resource", resource)):
        parsed = urlsplit(value if isinstance(value, str) else "")
        try:
            parsed_port = parsed.port
        except ValueError as exc:
            raise AdminError(f"Invalid OAuth {label}") from exc
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.fragment
        ):
            raise AdminError(f"Invalid OAuth {label}")
    if urlsplit(str(issuer)).path not in ("", "/") or urlsplit(str(issuer)).query:
        raise AdminError("OAuth issuer must be an HTTPS origin")
    if urlsplit(str(resource)).path != "/mcp" or urlsplit(str(resource)).query:
        raise AdminError("OAuth resource must be the canonical MCP URL")
    cert_file = Path(str(config.get("cert_file", "")))
    key_file = Path(str(config.get("key_file", "")))
    if not cert_file.is_absolute() or not key_file.is_absolute():
        raise AdminError("Admin TLS paths must be absolute")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(cert_file, key_file)
    return {
        **config,
        "bind": bind,
        "port": port,
        "allowed_hosts": normalized_hosts,
        "issuer": str(issuer).rstrip("/"),
        "resource": str(resource),
        "cert_file": str(cert_file),
        "key_file": str(key_file),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the LabSteward OAuth and admin interface")
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--check-config", action="store_true")
    args = parser.parse_args()
    try:
        config = validate_config(read_object(args.config))
        read_admin_credential()
        if args.check_config:
            print(f"valid LabSteward admin configuration for {config['issuer']}")
            return 0
        server = AdminServer((config["bind"], config["port"]), AdminHandler)
        server.allowed_hosts = config["allowed_hosts"]
        server.admin_sources = config["admin_sources"]
        server.enrollment_sources = config["enrollment_sources"]
        server.issuer = config["issuer"]
        server.resource = config["resource"]
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.options |= ssl.OP_NO_COMPRESSION
        context.load_cert_chain(config["cert_file"], config["key_file"])
        server.ssl_context = context
        server.serve_forever(poll_interval=0.5)
    except (AdminError, OSError, ValueError, ssl.SSLError) as exc:
        print(json.dumps({"event": "admin_service_failed", "reason": type(exc).__name__}), flush=True)
        return 1
    except KeyboardInterrupt:
        return 0
    finally:
        if "server" in locals():
            server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
