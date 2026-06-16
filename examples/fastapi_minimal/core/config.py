"""Service settings for the minimal example."""

from pathlib import Path

from pydantic_settings import SettingsConfigDict

from auth_sdk_m8.utils.paths import find_dotenv
from fastapi_m8 import ConsumerServiceSettings


class Settings(ConsumerServiceSettings):
    """Minimal consumer settings.

    fastapi-m8 >= 2.0.0 requires every consumer to declare its service/contract
    metadata (served at ``{API_PREFIX}/meta``, fail-closed at boot). A real
    service sets these from the environment like any other field; this no-``.env``
    example declares them inline so it stays runnable in a few lines.
    """

    ENV_FILE_DIR: Path = Path(__file__).resolve().parent.parent

    SERVICE_VERSION: str = "1.0.0"
    CONTRACT_VERSION: str = "1.0"
    CONTRACT_RANGE: str = ">=1.0.0 <2.0.0"

    model_config = SettingsConfigDict(
        env_file=find_dotenv(Path(__file__).resolve().parent.parent),
        env_file_encoding="utf-8",
        env_ignore_empty=True,
        extra="ignore",
    )


settings = Settings()
