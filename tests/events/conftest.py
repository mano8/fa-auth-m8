"""Shared fixtures for the event-stream bridge tests.

The hub and its metrics are process-global singletons, so every test starts
and ends with them reset — otherwise leaked state (a registered collector or a
bound hub) would bleed into the next test.
"""

import pytest

import auth_user_service.events.hub as hubmod
import auth_user_service.events.metrics as metmod


@pytest.fixture(autouse=True)
def _reset_event_state():
    hubmod._hub = None
    metmod.setup(False, "/user")
    yield
    hubmod._hub = None
    metmod.setup(False, "/user")
