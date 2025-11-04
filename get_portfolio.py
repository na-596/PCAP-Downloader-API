import requests
import os
import json
from datetime import datetime
from config import TOKEN_FILE, OAUTH_TOKEN_URL, SEARCH_API_URL, PORTFOLIO_AUTH_TOKEN, ensure_token_dir


"""Helpers to obtain an OAuth access token and lookup a portfolio ID.

This module caches a short-lived access token to a local token file (path is
provided via `TOKEN_FILE` in config). If the token is missing or expired, it
fetches a fresh token from the configured OAuth token endpoint and persists it.
"""


def _read_token_store():
    # Ensure token directory exists before attempting to read
    try:
        ensure_token_dir()
    except Exception:
        # If token dir creation fails, we'll still attempt to read and handle
        # missing files gracefully.
        pass

    if not TOKEN_FILE:
        return {}

    try:
        with open(TOKEN_FILE, "r") as f:
            return json.load(f)
    except Exception:
        # Missing or malformed token file is treated as empty cache
        return {}


def _write_token_store(data):
    # Ensure target directory exists and write the token JSON
    ensure_token_dir()
    with open(TOKEN_FILE, "w") as f:
        json.dump(data, f)


def get_access_token():
    """Return a cached access token or fetch a new one if expired.

    The token JSON is expected to contain an `expires_at` timestamp. We treat
    tokens as expired if they will expire within the next 60 seconds.
    """
    data = _read_token_store()
    now_ts = int(datetime.timestamp(datetime.now()))
    token_info = data.get("token")
    if token_info and token_info.get("expires_at", 0) > now_ts + 60:
        return token_info.get("access_token")

    # If not present or expired, fetch a new one using the provided auth token
    headers = {"Authorization": f"Bearer {PORTFOLIO_AUTH_TOKEN}"}
    resp = requests.post(OAUTH_TOKEN_URL, headers=headers)
    if resp.status_code != 200:
        raise RuntimeError("Failed to obtain access token")
    token_json = resp.json()
    access_token = token_json.get("access_token")
    expires_in = token_json.get("expires_in", 3600)
    token_record = {
        "access_token": access_token,
        "expires_at": now_ts + int(expires_in),
    }
    data["token"] = token_record
    _write_token_store(data)
    return access_token


def get_portfolio_id(iccid):
    """Lookup a portfolio ID for an ICCID using the SEARCH API.

    The function attaches a bearer token retrieved via get_access_token and
    returns the `portfolioId` field from the JSON response.
    """
    token = get_access_token()
    headers = {"Authorization": f"Bearer {token}"}
    params = {"iccid": iccid}
    resp = requests.get(f"{SEARCH_API_URL}/portfolio", headers=headers, params=params)
    if resp.status_code != 200:
        print(f"Failed to lookup portfolio: {resp.status_code}")
        return None
    data = resp.json()
    return data.get("portfolioId")

