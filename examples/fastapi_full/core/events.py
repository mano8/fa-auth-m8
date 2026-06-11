"""Auth event-stream wiring for fastapi_full.

Reference implementation of the fa-auth SSE bridge consumer.

The stream is a best-effort cache eviction accelerator — the JTI blacklist
(fa-auth) remains the revocation authority.  A missed event is safe (just
slower to converge); a replayed event is a no-op (idempotent eviction).
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING

from fastapi_m8 import AuthDeps, AuthStreamEvent, build_event_stream_client
from fastapi_m8.config import ConsumerServiceSettings

if TYPE_CHECKING:
    from fastapi import FastAPI

logger = logging.getLogger(__name__)


async def handle_auth_event(event: AuthStreamEvent, *, auth: AuthDeps) -> None:
    """Dispatch a verified auth stream event to the appropriate cache eviction.

    Dispatches on the signed ``payload["event_type"]`` per §5 signed-dispatch
    rule — never on the unsigned SSE ``event:`` field.
    """
    payload = event.payload
    event_type = payload.get("event_type")
    try:
        if event_type == "session.revoked":
            jti = payload.get("jti")
            user_id = payload.get("user_id", "")
            if jti:
                auth.evict_jti(jti)
            else:
                auth.evict_user(user_id)
        elif event_type == "user.deleted":
            auth.evict_user(payload.get("user_id", ""))
        else:
            logger.debug("auth_event_stream unknown_event_type=%s", event_type)
    except Exception:
        logger.exception("auth_event_stream handler failed event_type=%s", event_type)


async def handle_auth_gap(*, auth: AuthDeps) -> None:
    """Flush the entire validation cache on an unresumable stream gap."""
    try:
        auth.flush_cache()
    except Exception:
        logger.exception("auth_event_stream gap handler failed")


@asynccontextmanager
async def _stream_lifespan(
    settings: ConsumerServiceSettings,
    auth: AuthDeps,
):
    async def on_event(event: AuthStreamEvent) -> None:
        await handle_auth_event(event, auth=auth)

    async def on_gap() -> None:
        await handle_auth_gap(auth=auth)

    client = build_event_stream_client(settings, on_event=on_event, on_gap=on_gap)
    client.start()
    try:
        yield
    finally:
        await client.stop()


def make_lifespan_extras(
    settings: ConsumerServiceSettings,
    auth: AuthDeps,
):
    """Return a ``lifespan_extras`` factory for ``AppLifecycle``.

    Returns ``None`` when ``INTROSPECTION_URL`` is not configured (e.g. local
    stateless mode) so the app boots cleanly without a stream client.
    """
    if settings.INTROSPECTION_URL is None:
        return None

    @asynccontextmanager
    async def _extras(app: "FastAPI"):  # noqa: ARG001
        async with _stream_lifespan(settings, auth):
            yield

    return _extras
