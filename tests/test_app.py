"""Tests for Flask routes in app.py."""

from unittest.mock import MagicMock, patch

import pytest
import requests

import app as flask_app_module


@pytest.fixture
def mock_env():
    """Fake Wrangler env object with APP_ID and PRIVATE_KEY attributes."""
    env = MagicMock()
    env.APP_ID = "test-app-id"
    env.PRIVATE_KEY = "test-private-key"
    return env


@pytest.fixture(autouse=True)
def patch_credentials(monkeypatch):
    """Replace module-level credentials with test values."""
    monkeypatch.setattr(flask_app_module, "APP_ID", "test-app-id")
    monkeypatch.setattr(flask_app_module, "PRIVATE_KEY", "test-private-key")


@pytest.fixture
def client():
    """Flask test client with testing mode enabled."""
    flask_app_module.app.config["TESTING"] = True
    return flask_app_module.app.test_client()


class TestAuthStart:
    """Tests for GET /auth/start/<aspsp_name>."""

    def test_redirects_to_bank_url(self, client):
        """Route returns 302 redirect to the URL returned by start_auth."""
        bank_url = "https://bank.example.com/login"
        with patch("app.auth.start_auth", return_value=bank_url):
            response = client.get("/auth/start/Nordea", follow_redirects=False)
        assert response.status_code == 302
        assert response.headers["Location"] == bank_url

    def test_passes_aspsp_name(self, client):
        """Route forwards the aspsp_name path segment to start_auth."""
        bank_url = "https://bank.example.com/login"
        with patch("app.auth.start_auth", return_value=bank_url) as mock_start:
            client.get("/auth/start/Nordea", follow_redirects=False)
        assert mock_start.call_args.args[2] == "Nordea"

    def test_passes_aspsp_country_fi(self, client):
        """Route passes the hardcoded FI country code to start_auth."""
        bank_url = "https://bank.example.com/login"
        with patch("app.auth.start_auth", return_value=bank_url) as mock_start:
            client.get("/auth/start/Nordea", follow_redirects=False)
        assert mock_start.call_args.args[3] == "FI"


class TestAuthCallback:
    """Tests for GET /auth/callback."""

    def test_returns_json_session(self, client):
        """Route returns 200 JSON with session data for a valid code."""
        session_data = {"session_id": "sess-xyz", "accounts": []}
        with patch("app.auth.create_session", return_value=session_data):
            response = client.get("/auth/callback?code=test-code")
        assert response.status_code == 200
        assert response.json["session_id"] == "sess-xyz"

    def test_passes_code_to_create_session(self, client):
        """Route forwards the code query parameter to create_session."""
        stub = {"session_id": "s", "accounts": []}
        with patch("app.auth.create_session", return_value=stub) as mock_create:
            client.get("/auth/callback?code=my-auth-code")
        assert mock_create.call_args.args[2] == "my-auth-code"

    def test_returns_502_on_session_http_error(self, client):
        """Route returns 502 JSON when create_session raises HTTPError."""
        http_error = requests.exceptions.HTTPError("502 Bad Gateway")
        with patch("app.auth.create_session", side_effect=http_error):
            response = client.get("/auth/callback?code=test-code")
        assert response.status_code == 502
        assert "error" in response.json

    def test_returns_400_on_oauth_error(self, client):
        """Route returns 400 JSON when bank redirects with ?error= param."""
        response = client.get("/auth/callback?error=access_denied")
        assert response.status_code == 400
        assert response.json["error"] == "access_denied"

    def test_returns_400_on_missing_code(self, client):
        """Route returns 400 JSON when neither code nor error is present."""
        response = client.get("/auth/callback")
        assert response.status_code == 400
        assert "error" in response.json


class TestHome:
    """Tests for GET /."""

    def test_renders_bank_names(self, client):
        """Route renders HTML containing each bank name."""
        aspsps = [{"name": "Nordea"}, {"name": "OP"}]
        with patch("app.auth.list_aspsps", return_value=aspsps):
            response = client.get("/")
        assert response.status_code == 200
        assert b"Nordea" in response.data
        assert b"OP" in response.data

    def test_links_point_to_auth_start(self, client):
        """Each bank name links to /auth/start/<name>."""
        aspsps = [{"name": "Nordea"}]
        with patch("app.auth.list_aspsps", return_value=aspsps):
            response = client.get("/")
        assert b"/auth/start/Nordea" in response.data

    def test_returns_502_on_http_error(self, client):
        """Route returns 502 JSON when list_aspsps raises HTTPError."""
        http_error = requests.exceptions.HTTPError("502 Bad Gateway")
        with patch("app.auth.list_aspsps", side_effect=http_error):
            response = client.get("/")
        assert response.status_code == 502
        assert "error" in response.json

    def test_renders_empty_state(self, client):
        """Route renders empty-state message when no ASPSPs are returned."""
        with patch("app.auth.list_aspsps", return_value=[]):
            response = client.get("/")
        assert response.status_code == 200
        assert b"No banks available." in response.data
