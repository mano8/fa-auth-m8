"""Auth event-stream wiring for fastapi_full.

Reference implementation of the fa-auth SSE bridge consumer.

The stream is a best-effort cache eviction accelerator — the JTI blacklist
(fa-auth) remains the revocation authority.  A missed event is safe (just
slower to converge); a replayed event is a no-op (idempotent eviction).

Dispatch is delegated to ``AuthDeps.handle_auth_event`` / ``AuthDeps.flush_cache``
rather than re-derived here: the v2 generation watermark, ``event_id`` dedup and
hyphen/dot ``event_type`` normalization rules (§3.5.2) live in exactly one place
(``fastapi_m8``), and this example must not re-implement them.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import TYPE_CHECKING

from fastapi_m8 import AuthDeps, build_event_stream_client
from fastapi_m8.config import ConsumerServiceSettings

if TYPE_CHECKING:
    from fastapi import FastAPI


@asynccontextmanager
async def _stream_lifespan(
    settings: ConsumerServiceSettings,
    auth: AuthDeps,
):
    async def on_gap() -> None:
        auth.flush_cache()

    client = build_event_stream_client(
        settings, on_event=auth.handle_auth_event, on_gap=on_gap
    )
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
