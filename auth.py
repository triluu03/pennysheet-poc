"""Enable Banking API client — JWT generation and OAuth flow helpers."""

import time
from datetime import datetime, timedelta, timezone
from typing import Any

import jwt
import requests

BASE_URL = "https://api.enablebanking.com"


def build_jwt(app_id: str, private_key: str) -> str:
    """Build and sign a JWT for authenticating requests.

    Parameters
    ----------
    app_id : str
        The Enable Banking application UUID, used as the JWT ``kid`` header.
    private_key : str
        PEM-encoded RSA private key string.

    Returns
    -------
    str
        RS256-signed JWT string ready for use as a Bearer token.

    Raises
    ------
    jwt.exceptions.InvalidKeyError
        If ``private_key`` is not a valid PEM-encoded RSA private key.
    """
    now = int(time.time())
    payload = {
        "iss": "enablebanking.com",
        "aud": "api.enablebanking.com",
        "iat": now,
        "exp": now + 120,
    }
    return jwt.encode(
        payload,
        private_key,
        algorithm="RS256",
        headers={"kid": app_id},
    )


def start_auth(
    app_id: str,
    private_key: str,
    aspsp_name: str,
    aspsp_country: str,
    redirect_url: str,
    state: str,
) -> str:
    """Initiate bank authorization via the Enable Banking /auth endpoint.

    Parameters
    ----------
    app_id : str
        The Enable Banking application UUID.
    private_key : str
        PEM-encoded RSA private key string.
    aspsp_name : str
        Name of the bank (ASPSP) to authorize against (e.g. ``"Nordea"``).
    aspsp_country : str
        ISO 3166-1 alpha-2 country code of the bank (e.g. ``"FI"``).
    redirect_url : str
        URL the bank will redirect to after the user authenticates.
    state : str
        Unique string for correlating the callback to this request.

    Returns
    -------
    str
        The bank's authorization URL to redirect the user to.

    Raises
    ------
    requests.exceptions.HTTPError
        If the Enable Banking API returns a non-2xx response.
    """
    token = build_jwt(app_id, private_key)
    valid_until = (datetime.now(timezone.utc) + timedelta(days=90)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    body = {
        "aspsp": {"name": aspsp_name, "country": aspsp_country},
        "redirect_url": redirect_url,
        "state": state,
        "access": {"valid_until": valid_until},
        "psu_type": "personal",
    }
    response = requests.post(
        f"{BASE_URL}/auth",
        json=body,
        headers={"Authorization": f"Bearer {token}"},
    )
    response.raise_for_status()
    return response.json()["url"]


def create_session(app_id: str, private_key: str, code: str) -> dict[str, Any]:
    """Exchange an authorization code for an Enable Banking session.

    Parameters
    ----------
    app_id : str
        The Enable Banking application UUID.
    private_key : str
        PEM-encoded RSA private key string.
    code : str
        Authorization code received from the bank redirect callback.

    Returns
    -------
    dict[str, Any]
        Session payload from Enable Banking, containing ``session_id`` and
        ``accounts``.

    Raises
    ------
    requests.exceptions.HTTPError
        If the Enable Banking API returns a non-2xx response.
    """
    token = build_jwt(app_id, private_key)
    response = requests.post(
        f"{BASE_URL}/sessions",
        json={"code": code},
        headers={"Authorization": f"Bearer {token}"},
    )
    response.raise_for_status()
    return response.json()


def list_aspsps(app_id: str, private_key: str, country: str) -> list[dict]:
    """Fetch the list of available ASPSPs for a given country.

    Parameters
    ----------
    app_id : str
        The Enable Banking application UUID.
    private_key : str
        PEM-encoded RSA private key string.
    country : str
        ISO 3166-1 alpha-2 country code to filter ASPSPs by (e.g. ``"FI"``).

    Returns
    -------
    list[dict]
        List of ASPSP objects returned by Enable Banking.

    Raises
    ------
    requests.exceptions.HTTPError
        If the Enable Banking API returns a non-2xx response.
    """
    token = build_jwt(app_id, private_key)
    response = requests.get(
        f"{BASE_URL}/aspsps",
        params={"country": country},
        headers={"Authorization": f"Bearer {token}"},
    )
    response.raise_for_status()
    return response.json()["aspsps"]
