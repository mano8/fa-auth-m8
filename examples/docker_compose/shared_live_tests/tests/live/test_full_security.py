"""Full reusable live security suite for the hardened_m8 compose stack."""

import pytest
import requests

from security_tests_m8 import get_config
from security_tests_m8.full_security import *  # noqa: F403

pytestmark = [pytest.mark.live]


def test_fastapi_unknown_route_returns_404_without_internal_path() -> None:
    """The downstream service must not expose internals on unknown routes."""
    config = get_config()
    response = requests.get(
        f"{config.resolve_service_base_url('fastapi')}/no/such/route/",
        timeout=config.timeout,
    )

    assert response.status_code == 404
    assert "/opt/" not in response.text
    assert "Traceback" not in response.text
