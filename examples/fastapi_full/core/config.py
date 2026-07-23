"""Service settings for fastapi_full.

Extends ConsumerServiceSettings with service-specific fields only.
ConsumerAuthMixin, ObservabilitySettingsMixin, and CommonSettings are
all inherited via the base class.
"""

from pathlib import Path

from fastapi_m8 import ConsumerServiceSettings, find_dotenv
from pydantic_settings import SettingsConfigDict

from .. import __version__


class Settings(ConsumerServiceSettings):
    """fastapi_full settings — inherits all consumer fields from fastapi-m8.

    fastapi-m8 >= 2.0.0 requires every consumer to declare its service/contract
    metadata (served at ``{API_PREFIX}/meta``, fail-closed at boot). This example
    tracks its own package ``__version__`` (kept in step with the fa-auth-m8 repo)
    rather than a placeholder; a real standalone service sets these from its own
    package/env.
    """

    ENV_FILE_DIR: Path = Path(__file__).resolve().parent.parent

    SERVICE_VERSION: str = __version__
    CONTRACT_VERSION: str = "2.0"
    CONTRACT_RANGE: str = ">=2.0.0 <3.0.0"

    # Vault/`_FILE` source ordering is handled by the inherited
    # CommonSettings.settings_customise_sources classmethod — no override needed.
    model_config = SettingsConfigDict(
        env_file=find_dotenv(Path(__file__).resolve().parent.parent),
        env_file_encoding="utf-8",
        env_ignore_empty=True,
        extra="forbid",
    )


try:
    settings = Settings()
except Exception as exc:
    raise RuntimeError(f"Configuration validation error:\n {exc}") from exc
