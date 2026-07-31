"""Shared route-level exception-to-HTTP-response helpers."""

import logging
import uuid
from typing import Optional

from fastapi import HTTPException, status
from fastapi.responses import JSONResponse
from pydantic import ValidationError
from redis.exceptions import ConnectionError as RedisConnectionError
from sqlalchemy.exc import IntegrityError, OperationalError
from sqlmodel import Session

from auth_sdk_m8.controllers.base import BaseController

_logger = logging.getLogger(__name__)

# Exception categories whose caller-visible detail is built from *parsed*
# fields rather than from the exception text: an integrity error becomes
# table/column facts, a validation error becomes field/message pairs. Neither
# can carry a statement, so both are rendered from the original exception.
_STRUCTURED_ERRORS = (IntegrityError, ValidationError)

# The only detail any other failure may put in a response body. A driver
# exception stringifies to the statement it failed on, its bound parameters
# and the server's hint, so no response is ever rendered from an unrecognised
# exception (SEC-NO-SECRET-DISCLOSURE) — the full exception goes to the
# service log under a reference the caller can quote to support.
_OPAQUE_DETAIL = "An internal error occurred."


class RedactedError(Exception):
    """Stand-in rendered in place of an unrecognised exception.

    Carries only the generic detail and the log reference, so the standard
    error envelope is built without the real exception ever reaching it.
    """


def _redact(ex: Exception) -> RedactedError:
    """Log *ex* in full and return the caller-safe stand-in for it."""
    reference = uuid.uuid4().hex[:12]
    _logger.warning(
        "route.unhandled_exception ref=%s type=%s",
        reference,
        type(ex).__name__,
        exc_info=ex,
    )
    return RedactedError(f"{_OPAQUE_DETAIL} Reference: {reference}.")


def handle_route_exception(
    ex: Exception,
    session: Optional[Session] = None,
) -> JSONResponse:
    """Map a caught exception to the appropriate HTTP response.

    Raises HTTPException (not returns) for infrastructure failures so the
    correct status code reaches the client even when the caller uses ``return``.

    - HTTPException          → re-raised (preserves original status code)
    - OperationalError       → 503 (database unreachable)
    - RedisConnectionError   → 503 (cache unreachable)
    - IntegrityError /
      ValidationError        → rendered from the parsed error fields (400)
    - everything else        → logged in full, rendered as an opaque 500
    """
    if isinstance(ex, HTTPException):
        raise ex
    if isinstance(ex, OperationalError):
        if session:
            session.rollback()
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database temporarily unavailable. Please try again.",
        )
    if isinstance(ex, RedisConnectionError):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Cache service temporarily unavailable. Please try again.",
        )
    if not isinstance(ex, _STRUCTURED_ERRORS):
        ex = _redact(ex)
    return BaseController.handle_exception(ex=ex, session=session)
