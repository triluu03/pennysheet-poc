"""Tests for auth.py — JWT generation and Enable Banking API calls."""

import re
from unittest.mock import MagicMock, patch

import jwt
import pytest
import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

import auth

TEST_APP_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"


@pytest.fixture
def rsa_key_pair():
    """Generate a throwaway RSA key pair for testing JWT signing."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    public_key = private_key.public_key()
    return private_pem, public_key


def _mock_response(json_data: dict) -> MagicMock:
    """Build a mock ``requests.Response`` returning ``json_data``.

    Parameters
    ----------
    json_data : dict
        Data returned by ``response.json()``.

    Returns
    -------
    MagicMock
        Mock response with ``json`` and ``raise_for_status`` configured.
    """
    mock_resp = MagicMock()
    mock_resp.json.return_value = json_data
    return mock_resp


class TestBuildJwt:
    """Tests for ``build_jwt`` — synchronous, no HTTP calls."""

    def test_claims(self, rsa_key_pair):
        """JWT payload contains the required Enable Banking claims."""
        private_pem, public_key = rsa_key_pair
        token = auth.build_jwt(TEST_APP_ID, private_pem)
        payload = jwt.decode(
            token, public_key, algorithms=["RS256"], audience="api.enablebanking.com"
        )
        assert payload["iss"] == "enablebanking.com"
        assert payload["aud"] == "api.enablebanking.com"
        assert payload["exp"] == payload["iat"] + 3600

    def test_kid_header(self, rsa_key_pair):
        """JWT header carries the app UUID as ``kid`` and RS256 algorithm."""
        private_pem, _ = rsa_key_pair
        token = auth.build_jwt(TEST_APP_ID, private_pem)
        header = jwt.get_unverified_header(token)
        assert header["kid"] == TEST_APP_ID
        assert header["alg"] == "RS256"


class TestStartAuth:
    """Tests for ``start_auth`` — POSTs to /auth."""

    def test_returns_bank_url(self, rsa_key_pair):
        """Function returns the ``url`` field from the API response."""
        private_pem, _ = rsa_key_pair
        mock_resp = _mock_response({"url": "https://bank.example.com/auth"})
        with patch("auth.requests.post", return_value=mock_resp):
            url = auth.start_auth(
                TEST_APP_ID, private_pem, "Nordea", "FI",
                "http://localhost:8000/auth/callback", "state-xyz",
            )
        assert url == "https://bank.example.com/auth"

    def test_posts_to_correct_endpoint(self, rsa_key_pair):
        """Function POSTs to ``https://api.enablebanking.com/auth``."""
        private_pem, _ = rsa_key_pair
        mock_resp = _mock_response({"url": "https://bank.example.com/auth"})
        with patch("auth.requests.post", return_value=mock_resp) as mock_post:
            auth.start_auth(
                TEST_APP_ID, private_pem, "Nordea", "FI",
                "http://localhost:8000/auth/callback", "state-xyz",
            )
        assert mock_post.call_args.args[0] == "https://api.enablebanking.com/auth"

    def test_posts_correct_body(self, rsa_key_pair):
        """Function sends the expected JSON body fields."""
        private_pem, _ = rsa_key_pair
        mock_resp = _mock_response({"url": "https://bank.example.com/auth"})
        with patch("auth.requests.post", return_value=mock_resp) as mock_post:
            auth.start_auth(
                TEST_APP_ID, private_pem, "Nordea", "FI",
                "http://localhost:8000/auth/callback", "state-xyz",
            )
        body = mock_post.call_args.kwargs["json"]
        assert body["aspsp"] == {"name": "Nordea", "country": "FI"}
        assert body["redirect_url"] == "http://localhost:8000/auth/callback"
        assert body["state"] == "state-xyz"
        assert body["psu_type"] == "personal"
        assert "valid_until" in body["access"]

    def test_valid_until_is_iso8601(self, rsa_key_pair):
        """``access.valid_until`` is formatted as ``YYYY-MM-DDTHH:MM:SSZ``."""
        private_pem, _ = rsa_key_pair
        mock_resp = _mock_response({"url": "https://bank.example.com/auth"})
        with patch("auth.requests.post", return_value=mock_resp) as mock_post:
            auth.start_auth(
                TEST_APP_ID, private_pem, "Nordea", "FI",
                "http://localhost:8000/auth/callback", "state-xyz",
            )
        body = mock_post.call_args.kwargs["json"]
        valid_until = body["access"]["valid_until"]
        assert re.match(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", valid_until)

    def test_raises_on_http_error(self, rsa_key_pair):
        """Function propagates ``HTTPError`` from the API."""
        private_pem, _ = rsa_key_pair
        mock_resp = _mock_response({})
        mock_resp.raise_for_status.side_effect = requests.exceptions.HTTPError(
            "401 Unauthorized"
        )
        with patch("auth.requests.post", return_value=mock_resp):
            with pytest.raises(requests.exceptions.HTTPError):
                auth.start_auth(
                    TEST_APP_ID, private_pem, "Nordea", "FI",
                    "http://localhost:8000/auth/callback", "state-xyz",
                )

    def test_sends_bearer_token_header(self, rsa_key_pair):
        """Function attaches an ``Authorization: Bearer <jwt>`` header."""
        private_pem, _ = rsa_key_pair
        mock_resp = _mock_response({"url": "https://bank.example.com/auth"})
        with patch("auth.requests.post", return_value=mock_resp) as mock_post:
            auth.start_auth(
                TEST_APP_ID, private_pem, "Nordea", "FI",
                "http://localhost:8000/auth/callback", "state-xyz",
            )
        headers = mock_post.call_args.kwargs["headers"]
        assert "Authorization" in headers
        assert headers["Authorization"].startswith("Bearer ")


class TestCreateSession:
    """Tests for ``create_session`` — POSTs to /sessions."""

    def test_returns_session_payload(self, rsa_key_pair):
        """Function returns the full session payload from the API."""
        private_pem, _ = rsa_key_pair
        expected = {"session_id": "sess-abc", "accounts": [{"uid": "acc-1"}]}
        mock_resp = _mock_response(expected)
        with patch("auth.requests.post", return_value=mock_resp):
            result = auth.create_session(TEST_APP_ID, private_pem, "code-123")
        assert result == expected

    def test_posts_to_correct_endpoint(self, rsa_key_pair):
        """Function POSTs to ``https://api.enablebanking.com/sessions``."""
        private_pem, _ = rsa_key_pair
        mock_resp = _mock_response({"session_id": "s", "accounts": []})
        with patch("auth.requests.post", return_value=mock_resp) as mock_post:
            auth.create_session(TEST_APP_ID, private_pem, "code-123")
        assert mock_post.call_args.args[0] == "https://api.enablebanking.com/sessions"

    def test_posts_correct_body(self, rsa_key_pair):
        """Function sends ``{"code": <code>}`` as the JSON body."""
        private_pem, _ = rsa_key_pair
        mock_resp = _mock_response({"session_id": "s", "accounts": []})
        with patch("auth.requests.post", return_value=mock_resp) as mock_post:
            auth.create_session(TEST_APP_ID, private_pem, "code-123")
        assert mock_post.call_args.kwargs["json"] == {"code": "code-123"}

    def test_raises_on_http_error(self, rsa_key_pair):
        """Function propagates ``HTTPError`` from the API."""
        private_pem, _ = rsa_key_pair
        mock_resp = _mock_response({})
        mock_resp.raise_for_status.side_effect = requests.exceptions.HTTPError(
            "401 Unauthorized"
        )
        with patch("auth.requests.post", return_value=mock_resp):
            with pytest.raises(requests.exceptions.HTTPError):
                auth.create_session(TEST_APP_ID, private_pem, "code-123")

    def test_sends_bearer_token_header(self, rsa_key_pair):
        """Function attaches an ``Authorization: Bearer <jwt>`` header."""
        private_pem, _ = rsa_key_pair
        mock_resp = _mock_response({"session_id": "s", "accounts": []})
        with patch("auth.requests.post", return_value=mock_resp) as mock_post:
            auth.create_session(TEST_APP_ID, private_pem, "code-123")
        headers = mock_post.call_args.kwargs["headers"]
        assert "Authorization" in headers
        assert headers["Authorization"].startswith("Bearer ")


class TestListAspsps:
    """Tests for ``list_aspsps`` — GETs from /aspsps."""

    def test_returns_aspsps_list(self, rsa_key_pair):
        """Function returns the list from the API response."""
        private_pem, _ = rsa_key_pair
        mock_resp = _mock_response(
            {"aspsps": [{"name": "Nordea"}, {"name": "OP"}]}
        )
        with patch("auth.requests.get", return_value=mock_resp):
            result = auth.list_aspsps(TEST_APP_ID, private_pem, "FI")
        assert result == [{"name": "Nordea"}, {"name": "OP"}]

    def test_gets_from_correct_endpoint(self, rsa_key_pair):
        """Function GETs from the /aspsps endpoint."""
        private_pem, _ = rsa_key_pair
        mock_resp = _mock_response({"aspsps": []})
        with patch("auth.requests.get", return_value=mock_resp) as mock_get:
            auth.list_aspsps(TEST_APP_ID, private_pem, "FI")
        assert mock_get.call_args.args[0] == "https://api.enablebanking.com/aspsps"

    def test_sends_country_param(self, rsa_key_pair):
        """Function passes country as a query parameter."""
        private_pem, _ = rsa_key_pair
        mock_resp = _mock_response({"aspsps": []})
        with patch("auth.requests.get", return_value=mock_resp) as mock_get:
            auth.list_aspsps(TEST_APP_ID, private_pem, "FI")
        assert mock_get.call_args.kwargs["params"] == {"country": "FI"}

    def test_sends_bearer_token_header(self, rsa_key_pair):
        """Function includes Authorization Bearer header."""
        private_pem, _ = rsa_key_pair
        mock_resp = _mock_response({"aspsps": []})
        with patch("auth.requests.get", return_value=mock_resp) as mock_get:
            auth.list_aspsps(TEST_APP_ID, private_pem, "FI")
        headers = mock_get.call_args.kwargs["headers"]
        assert "Authorization" in headers
        assert headers["Authorization"].startswith("Bearer ")

    def test_raises_on_http_error(self, rsa_key_pair):
        """Function propagates HTTPError from the API."""
        private_pem, _ = rsa_key_pair
        mock_resp = _mock_response({})
        mock_resp.raise_for_status.side_effect = requests.exceptions.HTTPError(
            "401 Unauthorized"
        )
        with patch("auth.requests.get", return_value=mock_resp):
            with pytest.raises(requests.exceptions.HTTPError):
                auth.list_aspsps(TEST_APP_ID, private_pem, "FI")
