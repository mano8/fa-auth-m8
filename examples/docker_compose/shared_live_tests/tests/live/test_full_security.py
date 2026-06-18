"""Full reusable live security suite for the hardened_m8 compose stack."""

import pytest

from security_tests_m8.full_security import *  # noqa: F403

pytestmark = [pytest.mark.live]
