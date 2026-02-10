# Clean Python file -- contains NO secrets whatsoever.
# Used to verify that envguard does not produce false positives on safe code.

import os
from pathlib import Path


def get_config_path() -> Path:
    """Return the path to the application config directory."""
    return Path.home() / ".config" / "myapp"


def load_settings(path: Path) -> dict:
    """Load settings from a JSON file."""
    import json

    with path.open() as fh:
        return json.load(fh)


# Normal variable assignments that should NOT trigger detection.
API_VERSION = "v2"
TOKEN_EXPIRY_SECONDS = 3600
PASSWORD_MIN_LENGTH = 12
SECRET_ROTATION_DAYS = 90
MAX_KEY_LENGTH = 256

# A URL without credentials should be safe.
DATABASE_HOST = "db.example.com"
REDIS_URL = "redis://localhost:6379/0"

# Comments mentioning "key" or "secret" should not trigger anything.
# The API key is stored in the environment, not in this file.
# Remember to rotate the secret every 90 days.


class AuthConfig:
    """Authentication configuration container."""

    def __init__(self, provider: str, region: str):
        self.provider = provider
        self.region = region
        self.token_url = f"https://auth.{provider}.com/oauth/token"

    def get_api_key_from_env(self) -> str:
        """Retrieve the API key from an environment variable."""
        key = os.environ.get("APP_API_KEY", "")
        if not key:
            raise EnvironmentError("APP_API_KEY is not set")
        return key
