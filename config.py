from dotenv import load_dotenv
import os
import json
from pathlib import Path

load_dotenv()


def _load_json_env(name, default):
    val = os.getenv(name)
    if not val:
        return default
    try:
        return json.loads(val)
    except Exception:
        return [val]


# Token store path
TOKEN_FILE = os.getenv("TOKEN_STORE_PATH")


# Elastic search host template and credentials
ES_HOST_TEMPLATE = os.getenv("ES_HOST_TEMPLATE")
ES_USER = os.getenv("ES_USER")
ES_PASS = os.getenv("ES_PASS")


# Search API / portfolio lookup
OAUTH_TOKEN_URL = os.getenv("OAUTH_TOKEN_URL")
SEARCH_API_URL = os.getenv("SEARCH_API_URL")
PORTFOLIO_AUTH_TOKEN = os.getenv("PORTFOLIO_AUTH_TOKEN")


# Athena / S3 configuration
DATABASE = os.getenv("DATABASE")
BUCKET = os.getenv("BUCKET")

# SQL templates (optional - can be supplied via env)
SQL_QUERY_WITH_TIME_WINDOW = os.getenv("SQL_QUERY_WITH_TIME_WINDOW")
SQL_QUERY_WITHOUT_TIME_WINDOW = os.getenv("SQL_QUERY_WITHOUT_TIME_WINDOW")


# IP expressions and allowed codewords (JSON arrays expected in env)
IP_EXPRESSIONS = _load_json_env("IP_EXPRESSIONS", [])
ALLOWED_CODEWORDS = _load_json_env("ALLOWED_CODEWORDS", [])


def ensure_token_dir():
    # create parent directory for token file if it doesn't exist
    # TOKEN_FILE may be a path string; ensure we create the parent directory
    # safely if a path was provided. If TOKEN_FILE is not set, this function
    # becomes a no-op.
    if not TOKEN_FILE:
        return
    parent = Path(TOKEN_FILE).parent
    if not parent.exists():
        parent.mkdir(parents=True, exist_ok=True)
