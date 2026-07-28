"""Route-level exception-to-HTTP-response helper for this consumer.

Every route body funnels its ``except`` branch through
:func:`handle_route_exception` rather than calling ``BaseController`` directly,
so one place decides what a failure is allowed to tell a caller.
"""

import logging
import uuid
from typing import Optional

from fastapi import HTTPException
from fastapi.responses import JSONResponse
from pydantic import ValidationError
from sqlalchemy.exc import IntegrityError
from sqlmodel import Session

from fastapi_m8 import BaseController

_logger = logging.getLogger(__name__)

# Exception categories whose caller-visible detail is built from *parsed*
# fields rather than from the exception text: an integrity error becomes
# table/column facts, a validation error becomes field/message pairs. Neither
# can carry a statement, so both are rendered from the original exception.
_STRUCTURED_ERRORS = (IntegrityError, ValidationError)

# The only detail any other failure may put in a response body. A driver
# exception stringifies to the statement it failed on, its bound parameters
# and the server's hint, so no response is ever rendered from an unrecognised
# exception — the full exception goes to the application log under a reference
# the caller can quote to support.
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
    """Map a caught exception to its response, redacting anything unrecognised.

    Args:
        ex: The caught exception.
        session: Optional session to roll back.

    Returns:
        The standard error envelope — rendered from the parsed fields of an
        integrity or validation error, and from an opaque stand-in for every
        other failure.

    Raises:
        HTTPException: Re-raised unchanged so its status code is preserved.
    """
    if isinstance(ex, HTTPException):
        raise ex
    if not isinstance(ex, _STRUCTURED_ERRORS):
        ex = _redact(ex)
    return BaseController.handle_exception(ex=ex, session=session)
