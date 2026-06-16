"""Service settings for fastapi_full.

Extends ConsumerServiceSettings with service-specific fields only.
ConsumerAuthMixin, ObservabilitySettingsMixin, and CommonSettings are
all inherited via the base class.
"""

from pathlib import Path

from auth_sdk_m8.core.config import settings_customise_sources
from auth_sdk_m8.utils.paths import find_dotenv
from fastapi_m8 import ConsumerServiceSettings
from pydantic_settings import SettingsConfigDict


class Settings(ConsumerServiceSettings):
    """fastapi_full settings — inherits all consumer fields from fastapi-m8.

    fastapi-m8 >= 2.0.0 requires every consumer to declare its service/contract
    metadata (served at ``{API_PREFIX}/meta``, fail-closed at boot). Defaults are
    set here so the example stays valid without a committed ``.env``; a real
    deployment overrides them from the environment.
    """

    ENV_FILE_DIR: Path = Path(__file__).resolve().parent.parent

    SERVICE_VERSION: str = "1.0.0"
    CONTRACT_VERSION: str = "1.0"
    CONTRACT_RANGE: str = ">=1.0.0 <2.0.0"

    model_config = SettingsConfigDict(
        env_file=find_dotenv(Path(__file__).resolve().parent.parent),
        env_file_encoding="utf-8",
        env_ignore_empty=True,
        extra="forbid",
        settings_customise_sources=settings_customise_sources,  # type: ignore[typeddict-unknown-key]
    )


try:
    settings = Settings()
except Exception as exc:
    raise RuntimeError(f"Configuration validation error:\n {exc}") from exc
