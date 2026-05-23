"""Flask application for the Enable Banking OAuth authentication flow."""

import os
import uuid

import flask
import flask.typing
import requests
from dotenv import load_dotenv

import auth

load_dotenv()
APP_ID = os.getenv("APP_ID")
SANDBOX_PRIVATE_KEY = os.getenv("SANDBOX_PRIVATE_KEY")

ASPSP_COUNTRY = "FI"

REDIRECT_URL = "https://triluu03.pythonanywhere.com/auth/callback"
# REDIRECT_URL = "http://127.0.0.1:5000/auth/callback"
# REDIRECT_URL = "http://localhost:5000/auth/callback"

app = flask.Flask(__name__)


@app.route("/")
def home() -> flask.typing.ResponseReturnValue:
    """List available Finnish banks for authentication.

    Returns
    -------
    flask.typing.ResponseReturnValue
        Rendered HTML with a clickable list of ASPSPs on success, or a
        JSON error body with HTTP 502 if the Enable Banking API returns a
        non-2xx response.
    """
    if APP_ID is None or SANDBOX_PRIVATE_KEY is None:
        return {
            "error": (
                "Could not load the APP_ID or SANDBOX_PRIVATE_KEY environment "
                "variables"
            )
        }

    try:
        aspsps = auth.list_aspsps(APP_ID, SANDBOX_PRIVATE_KEY, ASPSP_COUNTRY)
    except requests.HTTPError as exc:
        return flask.jsonify({"error": str(exc)}), 502
    return flask.render_template("index.html", aspsps=aspsps)


@app.route("/status")
def status_check() -> flask.typing.ResponseReturnValue:
    """Check the status of the application.

    Returns
    -------
    flask.typing.ResponseReturnValue
        A simple JSON indicating that the application is working.

    """
    return {"status": "working"}


@app.route("/auth/start/<aspsp_name>")
def auth_start(aspsp_name: str) -> flask.typing.ResponseReturnValue:
    """Initiate bank authorization for the given ASPSP.

    Parameters
    ----------
    aspsp_name : str
        Name of the bank to authorize against (e.g. ``"Nordea"``).

    Returns
    -------
    flask.typing.ResponseReturnValue
        Redirect to the bank's authorization URL on success, or a JSON
        error body with HTTP 502 if the Enable Banking API returns a
        non-2xx response.
    """
    state = str(uuid.uuid4())
    try:
        bank_url = auth.start_auth(
            APP_ID,
            SANDBOX_PRIVATE_KEY,
            aspsp_name,
            ASPSP_COUNTRY,
            REDIRECT_URL,
            state,
        )
    except requests.HTTPError as exc:
        return flask.jsonify({"error": str(exc)}), 502
    return flask.redirect(bank_url)


@app.route("/auth/callback")
def auth_callback() -> flask.typing.ResponseReturnValue:
    """Handle the bank redirect and exchange the code for a session.

    Returns
    -------
    flask.typing.ResponseReturnValue
        JSON with ``session_id`` and ``accounts`` from Enable Banking on
        success, or a JSON error body with HTTP 400 if the bank returned
        an error or the ``code`` query parameter is missing.
    """
    error = flask.request.args.get("error")
    if error:
        return flask.jsonify({"error": error}), 400

    code = flask.request.args.get("code")
    if not code:
        return flask.jsonify({"error": "missing code parameter"}), 400

    try:
        session_data = auth.create_session(APP_ID, SANDBOX_PRIVATE_KEY, code)
    except requests.HTTPError as exc:
        return flask.jsonify({"error": str(exc)}), 502
    return flask.jsonify(session_data)


if __name__ == "__main__":
    app.run()
