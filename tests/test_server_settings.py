"""
Tests for HTTP server settings resolution and token auth middleware.
"""

import argparse
import asyncio
import os
import sys
from unittest.mock import patch

# Add the parent directory to the path so we can import our modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _import_server_helpers():
    """Import server settings helpers without triggering ADB initialization.

    server.py runs module-level code (config load, AdbDeviceManager) on import,
    so we import the functions via a guarded reload with ADB mocked out.
    """
    import importlib
    from unittest.mock import MagicMock, patch

    with patch("adbdevicemanager.AdbDeviceManager.check_adb_installed", return_value=True), \
            patch("adbdevicemanager.AdbDeviceManager.get_available_devices", return_value=["dev1"]), \
            patch("adbdevicemanager.AdbClient", return_value=MagicMock()):
        import server
        importlib.reload(server)
    return server


def _args(transport=None, host=None, port=None):
    return argparse.Namespace(transport=transport, host=host, port=port)


class TestServerSettings:
    """Test the config/env/CLI precedence in _server_settings."""

    def test_defaults(self):
        server = _import_server_helpers()
        with patch.dict(os.environ, {}, clear=True):
            s = server._server_settings({}, _args())
        assert s["transport"] == "streamable-http"
        assert s["host"] == "127.0.0.1"
        assert s["port"] == 8000
        assert s["auth_token"] == ""
        assert s["allowed_hosts"] == []
        assert s["ssl_certfile"] == ""
        assert s["ssl_keyfile"] == ""

    def test_tls_from_config(self):
        server = _import_server_helpers()
        config = {"server": {"ssl_certfile": "C:/certs/a.crt",
                             "ssl_keyfile": "C:/certs/a.key"}}
        with patch.dict(os.environ, {}, clear=True):
            s = server._server_settings(config, _args())
        assert s["ssl_certfile"] == "C:/certs/a.crt"
        assert s["ssl_keyfile"] == "C:/certs/a.key"

    def test_tls_env_overrides_config(self):
        server = _import_server_helpers()
        config = {"server": {"ssl_certfile": "C:/certs/a.crt"}}
        env = {"MCP_SSL_CERTFILE": "C:/certs/b.crt",
               "MCP_SSL_KEYFILE": "C:/certs/b.key"}
        with patch.dict(os.environ, env, clear=True):
            s = server._server_settings(config, _args())
        assert s["ssl_certfile"] == "C:/certs/b.crt"
        assert s["ssl_keyfile"] == "C:/certs/b.key"

    def test_config_values(self):
        server = _import_server_helpers()
        config = {"server": {"transport": "stdio", "host": "127.0.0.1",
                             "port": 9001, "auth_token": "secret",
                             "allowed_hosts": ["host:9001"]}}
        with patch.dict(os.environ, {}, clear=True):
            s = server._server_settings(config, _args())
        assert s["transport"] == "stdio"
        assert s["host"] == "127.0.0.1"
        assert s["port"] == 9001
        assert s["auth_token"] == "secret"
        assert s["allowed_hosts"] == ["host:9001"]

    def test_env_overrides_config(self):
        server = _import_server_helpers()
        config = {"server": {"host": "127.0.0.1", "port": 9001}}
        env = {"MCP_HOST": "10.0.0.5", "MCP_PORT": "7000",
               "MCP_AUTH_TOKEN": "envtoken"}
        with patch.dict(os.environ, env, clear=True):
            s = server._server_settings(config, _args())
        assert s["host"] == "10.0.0.5"
        assert s["port"] == 7000
        assert s["auth_token"] == "envtoken"

    def test_cli_overrides_env_and_config(self):
        server = _import_server_helpers()
        config = {"server": {"host": "127.0.0.1", "port": 9001}}
        env = {"MCP_HOST": "10.0.0.5", "MCP_PORT": "7000"}
        with patch.dict(os.environ, env, clear=True):
            s = server._server_settings(
                config, _args(host="192.168.0.10", port=5555, transport="sse"))
        assert s["host"] == "192.168.0.10"
        assert s["port"] == 5555
        assert s["transport"] == "sse"


class TestTokenAuthMiddleware:
    """Test the pure-ASGI bearer token middleware."""

    def _run(self, token, request_headers):
        server = _import_server_helpers()

        downstream_called = {"value": False}

        async def downstream(scope, receive, send):
            downstream_called["value"] = True
            await send({"type": "http.response.start", "status": 200,
                        "headers": []})
            await send({"type": "http.response.body", "body": b"ok"})

        middleware = server.TokenAuthMiddleware(downstream, token)

        sent = []

        async def send(message):
            sent.append(message)

        async def receive():
            return {"type": "http.request"}

        scope = {"type": "http", "headers": request_headers}
        asyncio.get_event_loop().run_until_complete(
            middleware(scope, receive, send))
        return downstream_called["value"], sent

    def test_valid_token_passes_through(self):
        called, sent = self._run(
            "secret", [(b"authorization", b"Bearer secret")])
        assert called is True
        assert sent[0]["status"] == 200

    def test_missing_token_rejected(self):
        called, sent = self._run("secret", [])
        assert called is False
        assert sent[0]["status"] == 401

    def test_wrong_token_rejected(self):
        called, sent = self._run(
            "secret", [(b"authorization", b"Bearer wrong")])
        assert called is False
        assert sent[0]["status"] == 401

    def test_lifespan_scope_passes_through(self):
        server = _import_server_helpers()

        downstream_called = {"value": False}

        async def downstream(scope, receive, send):
            downstream_called["value"] = True

        middleware = server.TokenAuthMiddleware(downstream, "secret")

        async def send(message):
            pass

        async def receive():
            return {"type": "lifespan.startup"}

        scope = {"type": "lifespan"}
        asyncio.get_event_loop().run_until_complete(
            middleware(scope, receive, send))
        assert downstream_called["value"] is True
