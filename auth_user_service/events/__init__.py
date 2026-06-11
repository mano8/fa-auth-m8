"""Auth event-stream bridge (fa-auth SSE publisher).

fa-auth fans its own auth-state events (session revoked / user deleted) out to
backend consumers over an authenticated SSE stream on the existing private API.
Push is a best-effort cache-eviction accelerator; the JTI blacklist remains the
revocation authority, so a missed event is still safe (just slower to converge).
"""

from auth_user_service.events.hub import (
    EVENT_SESSION_REVOKED,
    EVENT_USER_DELETED,
    EventHub,
    emit,
    get_hub,
    init_hub,
)

__all__ = [
    "EVENT_SESSION_REVOKED",
    "EVENT_USER_DELETED",
    "EventHub",
    "emit",
    "get_hub",
    "init_hub",
]
