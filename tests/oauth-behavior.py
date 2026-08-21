#!/usr/bin/env python3
"""End-to-end OAuth enrollment, browser approval, and revocation checks."""

from __future__ import annotations

import base64
import hashlib
import http.client
import json
import os
import re
import secrets
import socket
import ssl
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlsplit

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def choose_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def write_json(path: Path, value: object, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value) + "\n", encoding="utf-8")
    path.chmod(mode)


def request(
    port: int,
    context: ssl.SSLContext,
    method: str,
    path: str,
    *,
    body: bytes = b"",
    headers: dict[str, str] | None = None,
) -> tuple[int, dict[str, str], bytes]:
    connection = http.client.HTTPSConnection("127.0.0.1", port, timeout=5, context=context)
    values = {"Host": "127.0.0.1", **(headers or {})}
    if body:
        values["Content-Length"] = str(len(body))
    connection.request(method, path, body=body, headers=values)
    response = connection.getresponse()
    raw = response.read()
    response_headers = {key.lower(): value for key, value in response.getheaders()}
    status = response.status
    connection.close()
    return status, response_headers, raw


def form_body(values: dict[str, str]) -> bytes:
    return urlencode(values).encode("utf-8")


def broker_request(path: Path, operation: str, arguments: dict[str, object]) -> dict[str, object]:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(5)
        connection.connect(str(path))
        connection.sendall(
            json.dumps({"operation": operation, "arguments": arguments}).encode("utf-8") + b"\n"
        )
        raw = connection.makefile("rb").readline(65537)
    return json.loads(raw)


def wait_https(port: int, context: ssl.SSLContext, path: str) -> None:
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        try:
            status, _headers, _body = request(port, context, "GET", path)
            if status in {200, 400, 401, 403, 404}:
                return
        except OSError:
            pass
        time.sleep(0.05)
    raise AssertionError(f"HTTPS service on port {port} did not start")


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="labsteward-oauth-test.") as directory:
        fixture = Path(directory)
        cert = fixture / "server.crt"
        key = fixture / "server.key"
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                "-keyout", str(key), "-out", str(cert), "-days", "1",
                "-subj", "/CN=127.0.0.1", "-addext", "subjectAltName=IP:127.0.0.1",
                "-addext", "basicConstraints=critical,CA:TRUE",
                "-addext", "keyUsage=critical,digitalSignature,keyEncipherment,keyCertSign",
                "-addext", "extendedKeyUsage=serverAuth",
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        mcp_port = choose_port()
        admin_port = choose_port()
        config_file = fixture / "config.json"
        catalog_file = fixture / "plugins.json"
        version_file = fixture / "VERSION"
        oauth_tokens = fixture / "oauth-tokens.json"
        oauth_state = fixture / "oauth.json"
        credential_file = fixture / "admin-credential.json"
        broker_socket = fixture / "broker.sock"
        mcp_config = fixture / "transport.json"
        admin_config = fixture / "admin.json"
        plugins_dir = fixture / "plugins"
        (plugins_dir / "synology").mkdir(parents=True)
        for name in ("manifest.json", "plugin.py"):
            destination = plugins_dir / "synology" / name
            destination.write_bytes((PROJECT_ROOT / "plugins/synology" / name).read_bytes())
            destination.chmod(0o644)
        write_json(
            config_file,
            {
                "schema": 1,
                "plugins": {"proxmox": {"enabled": True, "version": "test"}},
                "servers": {
                    "pve-test": {
                        "plugin": "proxmox",
                        "endpoint": "https://pve.example.test:8006",
                    }
                },
                "clients": {},
            },
            0o640,
        )
        write_json(
            catalog_file,
            {
                "schema": 1,
                "plugins": [
                    {
                        "id": "proxmox",
                        "name": "Proxmox VE",
                        "status": "available",
                        "permissions": {
                            "audit.lxc": "write",
                            "audit.node": "write",
                            "audit.storage": "write",
                        },
                        "permission_descriptions": {
                            "audit.lxc": "Inspect or manage LXC workloads.",
                            "audit.node": "Inspect or manage Proxmox nodes.",
                            "audit.storage": "Inspect or manage Proxmox storage.",
                        },
                    },
                    {
                        "id": "synology",
                        "name": "Synology DSM",
                        "status": "available",
                        "version": "0.1.0",
                        "permissions": {"storage.read": "read", "system.read": "read"},
                        "permission_descriptions": {
                            "storage.read": "Read storage pool, volume, capacity, and aggregate disk health.",
                            "system.read": "Read DSM system health and bounded resource utilization.",
                        },
                    },
                ],
            },
            0o644,
        )
        version_file.write_text("v0.2.0\n", encoding="utf-8")
        password = "correct horse battery staple"
        salt = secrets.token_bytes(16)
        digest = hashlib.scrypt(
            password.encode(), salt=salt, n=2**15, r=8, p=1, dklen=32,
            maxmem=64 * 1024 * 1024,
        )
        write_json(
            credential_file,
            {
                "schema": 1, "algorithm": "scrypt", "username": "steward",
                "salt": base64.b64encode(salt).decode(),
                "digest": base64.b64encode(digest).decode(),
                "n": 2**15, "r": 8, "p": 1,
            },
        )
        resource = f"https://127.0.0.1:{mcp_port}/mcp"
        issuer = f"https://127.0.0.1:{admin_port}"
        write_json(
            mcp_config,
            {
                "schema": 1, "bind": "127.0.0.1", "port": mcp_port,
                "allowed_hosts": ["127.0.0.1"], "cert_file": str(cert),
                "key_file": str(key), "resource": resource,
                "authorization_servers": [issuer],
            },
        )
        write_json(
            admin_config,
            {
                "schema": 1, "bind": "127.0.0.1", "port": admin_port,
                "allowed_hosts": ["127.0.0.1"], "admin_sources": ["127.0.0.1/32"],
                "enrollment_sources": ["127.0.0.1/32"], "issuer": issuer,
                "resource": resource, "cert_file": str(cert), "key_file": str(key),
            },
        )
        common = os.environ.copy()
        common.update(
            {
                "PYTHONPATH": str(PROJECT_ROOT / "src"),
                "LABSTEWARD_CONFIG_FILE": str(config_file),
                "LABSTEWARD_CATALOG_FILE": str(catalog_file),
                "LABSTEWARD_VERSION_FILE": str(version_file),
                "LABSTEWARD_CLIENT_SECRETS_DIR": str(fixture / "legacy-clients"),
                "LABSTEWARD_OAUTH_TOKEN_FILE": str(oauth_tokens),
                "LABSTEWARD_BROKER_SOCKET": str(broker_socket),
                "LABSTEWARD_PLUGINS_DIR": str(plugins_dir),
            }
        )
        broker_environment = {**common, "LABSTEWARD_BROKER_ALLOW_CURRENT_UID": "1"}
        broker = subprocess.Popen(
            [sys.executable, str(PROJECT_ROOT / "src/labsteward_broker.py"), "--socket", str(broker_socket)],
            env=broker_environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        deadline = time.monotonic() + 5
        while not broker_socket.exists() and time.monotonic() < deadline:
            time.sleep(0.05)
        require(broker_socket.exists(), "broker socket did not start")
        invalid_endpoint = broker_request(
            broker_socket,
            "server.add",
            {
                "server": "invalid-port",
                "plugin": "proxmox",
                "endpoint": "https://example.test:not-a-port",
            },
        )
        require(
            invalid_endpoint.get("ok") is False
            and "invalid port" in str(invalid_endpoint.get("error", "")),
            "broker must reject malformed endpoint ports",
        )
        admin_environment = {
            **common,
            "LABSTEWARD_ADMIN_CONFIG": str(admin_config),
            "LABSTEWARD_ADMIN_CREDENTIAL": str(credential_file),
            "LABSTEWARD_OAUTH_STATE": str(oauth_state),
        }
        admin = subprocess.Popen(
            [sys.executable, str(PROJECT_ROOT / "src/labsteward_admin.py"), "--config", str(admin_config)],
            env=admin_environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        mcp_environment = {**common, "LABSTEWARD_TRANSPORT_CONFIG": str(mcp_config)}
        mcp = subprocess.Popen(
            [sys.executable, str(PROJECT_ROOT / "src/labsteward_mcp.py"), "--config", str(mcp_config)],
            env=mcp_environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        context = ssl.create_default_context(cafile=str(cert))
        access = refresh = second_access = ""
        try:
            wait_https(admin_port, context, "/.well-known/oauth-authorization-server")
            wait_https(mcp_port, context, "/.well-known/oauth-protected-resource/mcp")
            status, _headers, body = request(
                admin_port, context, "GET", "/.well-known/oauth-authorization-server"
            )
            metadata = json.loads(body)
            require(
                status == 200
                and metadata.get("token_endpoint_auth_methods_supported") == ["none"]
                and metadata.get("code_challenge_methods_supported") == ["S256"]
                and metadata.get("scopes_supported") == ["mcp:connect"],
                "authorization metadata must advertise the supported public-client profile",
            )
            status, headers, body = request(admin_port, context, "GET", "/favicon.png")
            require(
                status == 200
                and headers.get("content-type") == "image/png"
                and body.startswith(b"\x89PNG\r\n\x1a\n"),
                "the embedded LabSteward favicon must be served as a PNG",
            )
            status, _headers, body = request(
                admin_port, context, "POST", "/oauth/register",
                body=json.dumps({"client_name": "Codex Desktop", "redirect_uris": ["https://evil.example/callback"]}).encode(),
                headers={"Content-Type": "application/json"},
            )
            require(status == 400, "non-loopback OAuth redirect must be rejected")
            callback = "http://127.0.0.1:49152/callback/test"
            status, _headers, body = request(
                admin_port, context, "POST", "/oauth/register",
                body=json.dumps(
                    {"client_name": "Codex Desktop", "redirect_uris": [callback], "token_endpoint_auth_method": "none"}
                ).encode(),
                headers={"Content-Type": "application/json"},
            )
            require(status == 201, "dynamic client registration must succeed")
            registration = json.loads(body)
            protocol_client = registration["client_id"]
            verifier = secrets.token_urlsafe(48)
            challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
            query = urlencode(
                {
                    "response_type": "code", "client_id": protocol_client,
                    "redirect_uri": callback, "code_challenge": challenge,
                    "code_challenge_method": "S256", "state": "client-state",
                    "scope": "mcp:connect", "resource": resource,
                }
            )
            status, _headers, body = request(admin_port, context, "GET", f"/authorize?{query}")
            require(
                status == 200
                and b"Administrator sign in" in body
                and b"rel=icon" in body
                and b"class=login-brand" in body,
                "authorization must require the branded admin sign-in",
            )
            transaction = re.search(rb'name=transaction value=\'([^\']+)\'', body)
            require(transaction is not None, "authorization transaction missing")
            transaction_value = transaction.group(1).decode()
            login = form_body({"username": "steward", "password": password, "transaction": transaction_value})
            status, headers, _login_body = request(
                admin_port, context, "POST", "/admin/login", body=login,
                headers={"Content-Type": "application/x-www-form-urlencoded", "Origin": issuer},
            )
            require(status == 303 and "set-cookie" in headers, "administrator login must establish a session")
            cookie = headers["set-cookie"].split(";", 1)[0]
            location = headers["location"]
            status, _headers, body = request(
                admin_port, context, "GET", location, headers={"Cookie": cookie},
            )
            require(status == 200 and b"Trust this MCP client?" in body, "consent page missing")
            csrf = re.search(rb'name=csrf value=\'([^\']+)\'', body)
            require(csrf is not None, "consent CSRF token missing")
            approval = form_body(
                {
                    "csrf": csrf.group(1).decode(), "transaction": transaction_value,
                    "client": "desktop", "source": "127.0.0.1/32", "decision": "approve",
                }
            )
            status, headers, approval_body = request(
                admin_port, context, "POST", "/authorize", body=approval,
                headers={"Content-Type": "application/x-www-form-urlencoded", "Origin": issuer, "Cookie": cookie},
            )
            require(
                status == 303,
                f"client approval must redirect to the OAuth callback (status {status}: {approval_body[:1000]!r})",
            )
            callback_values = parse_qs(urlsplit(headers["location"]).query)
            code = callback_values["code"][0]
            require(callback_values["state"] == ["client-state"], "OAuth state must round-trip")
            exchange = form_body(
                {
                    "grant_type": "authorization_code", "client_id": protocol_client,
                    "redirect_uri": callback, "code": code, "code_verifier": verifier,
                }
            )
            status, _headers, body = request(
                admin_port, context, "POST", "/oauth/token", body=exchange,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            require(status == 200, "authorization code exchange must succeed")
            tokens = json.loads(body)
            access, refresh = tokens["access_token"], tokens["refresh_token"]
            require(access.startswith("lsa_") and refresh.startswith("lsr_"), "OAuth token prefixes invalid")
            initialize = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}).encode()
            status, _headers, body = request(
                mcp_port, context, "POST", "/mcp", body=initialize,
                headers={"Authorization": f"Bearer {access}", "Content-Type": "application/json"},
            )
            require(status == 200 and json.loads(body)["result"]["serverInfo"]["name"] == "labsteward", "OAuth access token must authenticate to MCP")
            status, headers, _body = request(
                mcp_port, context, "POST", "/mcp", body=initialize,
                headers={"Content-Type": "application/json"},
            )
            require(status == 401 and "resource_metadata=" in headers.get("www-authenticate", ""), "MCP challenge must advertise protected-resource metadata")
            refresh_body = form_body(
                {"grant_type": "refresh_token", "client_id": protocol_client, "refresh_token": refresh}
            )
            status, _headers, body = request(
                admin_port, context, "POST", "/oauth/token", body=refresh_body,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            require(status == 200, "refresh token rotation must succeed")
            second_access = json.loads(body)["access_token"]
            status, _headers, _body = request(
                admin_port, context, "POST", "/oauth/token", body=refresh_body,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            require(status == 400, "rotated refresh token must not be reusable")
            status, _headers, body = request(
                admin_port, context, "GET", "/admin", headers={"Cookie": cookie},
            )
            require(status == 200 and b"Codex Desktop" in body, "dashboard must list the approved client")
            require(
                b"class=brand" in body
                and b"src=/favicon.png" in body
                and b"<h1>LABSteward</h1>" in body
                and b"Administration" not in body,
                "dashboard header must show only the logo and title",
            )
            require(b"No servers have been added" in body, "new clients must not list every registered server")
            require(b"Add server" in body and b"pve-test" in body, "client card must offer explicit server assignment")
            require(b"<h2>Servers" not in body and b"<h2>Plugins" not in body, "main page must focus on clients")
            status, _headers, server_page = request(
                admin_port, context, "GET", "/admin/servers", headers={"Cookie": cookie},
            )
            require(status == 200 and b"Configure access" in server_page, "servers must have a separate page")
            status, _headers, plugin_page = request(
                admin_port, context, "GET", "/admin/plugins", headers={"Cookie": cookie},
            )
            require(status == 200 and b"Proxmox VE" in plugin_page, "plugins must have a separate page")
            require(b"Synology DSM" in plugin_page and b">Install</button>" in plugin_page, "available Synology plugin must be installable")
            plugin_csrf = re.search(rb'name=csrf value=\'([^\']+)\'', plugin_page)
            install_plugin = form_body({"csrf": plugin_csrf.group(1).decode(), "plugin": "synology"})
            status, _headers, plugin_page = request(
                admin_port, context, "POST", "/admin/plugin/install", body=install_plugin,
                headers={"Content-Type": "application/x-www-form-urlencoded", "Origin": issuer, "Cookie": cookie},
            )
            require(status == 200 and b"installed 0.1.0" in plugin_page, "verified Synology plugin install must succeed")
            require(
                json.loads(config_file.read_text(encoding="utf-8"))["plugins"]["synology"]
                == {"enabled": True, "version": "0.1.0"},
                "plugin install must register the exact released version",
            )
            dashboard_csrf = re.search(rb'name=csrf value=\'([^\']+)\'', body)
            assignment = form_body(
                {"csrf": dashboard_csrf.group(1).decode(), "client": "desktop", "server": "pve-test"}
            )
            status, _headers, body = request(
                admin_port, context, "POST", "/admin/client/server/add", body=assignment,
                headers={"Content-Type": "application/x-www-form-urlencoded", "Origin": issuer, "Cookie": cookie},
            )
            require(status == 200 and b"<details class=access-row>" in body, "assigned server must render collapsed")
            require(b"<details class=access-row open" not in body, "client server rows must be collapsed by default")
            require(b"class=collapse-icon" in body and b">Expand<" not in body, "collapsed rows must use a chevron icon")
            require(
                b"name='permission.audit.node'" in body
                and b"value='off'" in body
                and b"value='read'" in body
                and b"value='write'" in body
                and b"Inspect or manage Proxmox nodes." in body
                and re.search(rb"<input type=radio[^>]*disabled", body) is None,
                "client permissions must be vertical, described, consistent three-state controls",
            )
            status, _headers, _body = request(
                admin_port, context, "POST", "/admin/client/server/add", body=assignment,
                headers={"Content-Type": "application/x-www-form-urlencoded", "Origin": issuer, "Cookie": cookie},
            )
            require(status == 400, "the same server must not be assigned to a client twice")
            grant = form_body(
                {
                    "csrf": dashboard_csrf.group(1).decode(),
                    "client": "desktop",
                    "server": "pve-test",
                    "permission.audit.node": "write",
                }
            )
            status, _headers, body = request(
                admin_port, context, "POST", "/admin/client/grants", body=grant,
                headers={"Content-Type": "application/x-www-form-urlencoded", "Origin": issuer, "Cookie": cookie},
            )
            require(status == 200 and b"class=access-row" in body, "checkbox grant update must succeed")
            require(
                json.loads(config_file.read_text(encoding="utf-8"))["clients"]["desktop"]["grants"]["pve-test"]
                == {"audit.node": "write"},
                "selected client permission levels must become the exact grant",
            )
            remove_server = form_body({"csrf": dashboard_csrf.group(1).decode(), "server": "pve-test"})
            status, _headers, _body = request(
                admin_port, context, "POST", "/admin/server/remove", body=remove_server,
                headers={"Content-Type": "application/x-www-form-urlencoded", "Origin": issuer, "Cookie": cookie},
            )
            require(status == 200, "server removal must succeed while assigned to clients")
            require(
                "pve-test" not in json.loads(config_file.read_text(encoding="utf-8"))["clients"]["desktop"]["grants"],
                "server removal must cascade through every client grant",
            )
            revoke = form_body({"csrf": dashboard_csrf.group(1).decode(), "client": "desktop"})
            status, _headers, _body = request(
                admin_port, context, "POST", "/admin/client/revoke", body=revoke,
                headers={"Content-Type": "application/x-www-form-urlencoded", "Origin": issuer, "Cookie": cookie},
            )
            require(status == 200, "dashboard client revocation must succeed")
            require(
                "desktop" not in json.loads(config_file.read_text(encoding="utf-8"))["clients"],
                "revoked client must be removed from the registry and list",
            )
            status, _headers, _body = request(
                mcp_port, context, "POST", "/mcp", body=initialize,
                headers={"Authorization": f"Bearer {second_access}", "Content-Type": "application/json"},
            )
            require(status == 401, "revoked client access must fail immediately")
            unsupported = broker_request(broker_socket, "shell.run", {"command": "id"})
            require(unsupported.get("ok") is False, "broker must reject arbitrary operations")
            reapproval = broker_request(
                broker_socket,
                "client.approve",
                {
                    "client": "desktop", "display_name": "Codex Desktop",
                    "source": "127.0.0.1/32", "oauth_client_id": protocol_client,
                },
            )
            require(
                reapproval.get("ok") is True
                and reapproval.get("result", {}).get("auth_generation") == 2,
                "reapproval must advance the client authentication generation",
            )
            stale_generation = broker_request(
                broker_socket,
                "token.put",
                {
                    "digest": "a" * 64, "client": "desktop",
                    "expires_at": int(time.time()) + 300, "auth_generation": 1,
                },
            )
            require(stale_generation.get("ok") is False, "old refresh-token generations must stay revoked")
            stored_text = "\n".join(
                path.read_text(encoding="utf-8")
                for path in (config_file, oauth_state, oauth_tokens)
                if path.exists()
            )
            for plaintext in (access, refresh, second_access, password):
                require(plaintext not in stored_text, "plaintext credentials must not be persisted")
        finally:
            for process in (mcp, admin, broker):
                process.terminate()
            logs = ""
            for process in (mcp, admin, broker):
                try:
                    stdout, stderr = process.communicate(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    stdout, stderr = process.communicate(timeout=5)
                logs += stdout + stderr
        for plaintext in (access, refresh, second_access, password):
            require(not plaintext or plaintext not in logs, "plaintext credentials must not appear in service logs")
    print("OAuth and administrator behavior checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
