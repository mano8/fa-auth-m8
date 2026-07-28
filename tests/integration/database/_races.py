"""Classifying a lost race (``TEST-DB-01``).

The three certified engines refuse a losing transaction differently, and a Layer
B assertion must be about the invariant rather than about one engine's
mechanism. PostgreSQL blocks on the row lock and lets the application's own
guard refuse the loser; MySQL/MariaDB may abort it outright. Both are correct.
"""

from __future__ import annotations

from sqlalchemy.exc import (
    DBAPIError,
    InternalError,
    InvalidRequestError,
    OperationalError,
)

#: Ways a transaction can lose a race without anything being wrong:
#:
#: * the engine aborts it — a deadlock, a lock-wait timeout, PostgreSQL's
#:   serialization failure, or MariaDB's ``1020 Record has changed since last
#:   read``;
#: * the row it just wrote is revoked before it can be re-read — the login path
#:   commits and then ``refresh()``es its session row, and a role change landing
#:   in between deletes that row, so SQLAlchemy reports "Could not refresh
#:   instance". That is the downgrade doing exactly its job: the caller gets an
#:   error instead of a token that would be denied on first use.
#:
#: All of them mean "did not end up with usable authority", which is what the
#: races assert. None of them is a test error.
LOST_RACE_ERRORS = (OperationalError, InternalError, DBAPIError, InvalidRequestError)

LOST_RACE_MARKERS = (
    "deadlock",
    "lock wait timeout",
    "record has changed since last read",
    "could not serialize",
    "concurrent update",
    "could not refresh instance",
)


def is_serialization_failure(exc: BaseException) -> bool:
    """Whether *exc* is a lost race rather than a real fault."""
    if not isinstance(exc, LOST_RACE_ERRORS):
        return False
    text = str(exc).lower()
    return any(marker in text for marker in LOST_RACE_MARKERS)
