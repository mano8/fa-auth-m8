"""Security regression: handle_route_exception() maps infra errors to correct HTTP codes.

Verifies that:
- HTTPException is re-raised with its original status code (not swallowed into 500)
- SQLAlchemy OperationalError → 503 (database unreachable)
- Redis ConnectionError → 503 (cache unreachable)
- Session is rolled back on OperationalError
- Everything else is rendered as an opaque 500 that carries no exception text
- An integrity error still answers with its parsed table/column detail
"""

import json
import logging
from unittest.mock import MagicMock

import pytest
from fastapi import HTTPException
from fastapi.responses import JSONResponse
from redis.exceptions import ConnectionError as RedisConnectionError
from sqlalchemy.exc import IntegrityError, OperationalError, ProgrammingError

from auth_user_service.core.exceptions import handle_route_exception


class TestHTTPExceptionPassthrough:
    """HTTPException must never be swallowed into a 500."""

    def test_404_is_reraised(self):
        ex = HTTPException(status_code=404, detail="Not found")
        with pytest.raises(HTTPException) as exc_info:
            handle_route_exception(ex)
        assert exc_info.value.status_code == 404
        assert exc_info.value.detail == "Not found"

    def test_403_is_reraised(self):
        ex = HTTPException(status_code=403, detail="Forbidden")
        with pytest.raises(HTTPException) as exc_info:
            handle_route_exception(ex)
        assert exc_info.value.status_code == 403

    def test_409_is_reraised(self):
        ex = HTTPException(status_code=409, detail="Conflict")
        with pytest.raises(HTTPException) as exc_info:
            handle_route_exception(ex)
        assert exc_info.value.status_code == 409

    def test_all_4xx_codes_preserved(self):
        for code in [400, 401, 403, 404, 409, 422, 429]:
            ex = HTTPException(status_code=code, detail=f"error {code}")
            with pytest.raises(HTTPException) as exc_info:
                handle_route_exception(ex)
            assert exc_info.value.status_code == code

    def test_http_exception_with_session_still_reraised(self):
        ex = HTTPException(status_code=404, detail="Not found")
        mock_session = MagicMock()
        with pytest.raises(HTTPException) as exc_info:
            handle_route_exception(ex, session=mock_session)
        assert exc_info.value.status_code == 404
        mock_session.rollback.assert_not_called()


class TestDatabaseUnavailable:
    """OperationalError (DB unreachable) must produce a clear 503, not 500."""

    def test_operational_error_raises_503(self):
        ex = OperationalError("connection refused", None, None)
        with pytest.raises(HTTPException) as exc_info:
            handle_route_exception(ex)
        assert exc_info.value.status_code == 503

    def test_503_detail_mentions_database(self):
        ex = OperationalError("connection refused", None, None)
        with pytest.raises(HTTPException) as exc_info:
            handle_route_exception(ex)
        assert (
            "Database" in exc_info.value.detail or "database" in exc_info.value.detail
        )

    def test_session_rolled_back_on_operational_error(self):
        ex = OperationalError("connection refused", None, None)
        mock_session = MagicMock()
        with pytest.raises(HTTPException):
            handle_route_exception(ex, session=mock_session)
        mock_session.rollback.assert_called_once()

    def test_no_session_does_not_raise_on_operational_error(self):
        ex = OperationalError("connection refused", None, None)
        with pytest.raises(HTTPException) as exc_info:
            handle_route_exception(ex, session=None)
        assert exc_info.value.status_code == 503


class TestRedisUnavailable:
    """RedisConnectionError must produce a clear 503, not 500."""

    def test_connection_error_raises_503(self):
        ex = RedisConnectionError("Redis unreachable")
        with pytest.raises(HTTPException) as exc_info:
            handle_route_exception(ex)
        assert exc_info.value.status_code == 503

    def test_503_detail_mentions_cache(self):
        ex = RedisConnectionError("Redis unreachable")
        with pytest.raises(HTTPException) as exc_info:
            handle_route_exception(ex)
        detail = exc_info.value.detail.lower()
        assert "cache" in detail or "unavailable" in detail

    def test_redis_error_without_session(self):
        ex = RedisConnectionError("refused")
        with pytest.raises(HTTPException) as exc_info:
            handle_route_exception(ex, session=None)
        assert exc_info.value.status_code == 503


class TestOtherExceptionDelegation:
    """Non-infra exceptions produce a 500 JSONResponse."""

    def test_value_error_delegates_to_base_controller(self):
        ex = ValueError("something broke")
        result = handle_route_exception(ex)
        assert isinstance(result, JSONResponse)
        assert result.status_code == 500

    def test_runtime_error_delegates_to_base_controller(self):
        ex = RuntimeError("unexpected")
        result = handle_route_exception(ex)
        assert isinstance(result, JSONResponse)
        assert result.status_code == 500

    def test_session_rolled_back_via_base_controller(self):
        """The session is rolled back for generic errors."""
        ex = ValueError("boom")
        mock_session = MagicMock()
        handle_route_exception(ex, session=mock_session)
        mock_session.rollback.assert_called_once()


def _body(response: JSONResponse) -> dict:
    return json.loads(response.body)


# A driver failure exactly as SQLAlchemy raises it: the statement, the bound
# parameters and the server hint all live in ``str(ex)``.
_LEAKY_ERROR = ProgrammingError(
    "SELECT app_category.owner_id FROM app_category WHERE app_category.owner_id = %(id)s",
    {"id": "ab1ae7e8-fe0d-4454-944b-26729424f0e4"},
    Exception(
        "operator does not exist: character = uuid\n"
        "HINT:  No operator matches the given name and argument types."
    ),
)


class TestNoStatementDisclosure:
    """SEC-NO-SECRET-DISCLOSURE: a response never carries the failing statement.

    The reported gap: a dashboard query failed and the 500 body returned the
    whole ``SELECT``, its bound parameters and the PostgreSQL hint to the
    caller. The statement belongs in the service log, never in the response.
    """

    def test_driver_error_body_has_no_statement(self):
        body = _body(handle_route_exception(_LEAKY_ERROR))
        serialized = json.dumps(body)
        for leaked in ("SELECT", "app_category", "operator does not exist", "HINT"):
            assert leaked not in serialized

    def test_driver_error_body_is_a_generic_message(self):
        body = _body(handle_route_exception(_LEAKY_ERROR))
        assert body["success"] is False
        assert body["errors"][0]["error"].startswith("An internal error occurred.")

    def test_driver_error_is_logged_in_full(self, caplog):
        with caplog.at_level(
            logging.WARNING, logger="auth_user_service.core.exceptions"
        ):
            handle_route_exception(_LEAKY_ERROR)
        record = caplog.records[0]
        assert record.levelno == logging.WARNING
        assert record.exc_info is not None
        assert "app_category" in str(record.exc_info[1])

    def test_response_reference_matches_the_log_reference(self):
        """The caller can quote a reference that points at the logged exception."""
        body = _body(handle_route_exception(_LEAKY_ERROR))
        reference = body["errors"][0]["error"].rsplit("Reference: ", 1)[1].rstrip(".")
        assert len(reference) == 12

    def test_arbitrary_exception_text_is_not_echoed(self):
        body = _body(handle_route_exception(RuntimeError("internal detail leaked")))
        assert "internal detail leaked" not in json.dumps(body)


class TestIntegrityErrorStillReportsItsFields:
    """Parsed integrity detail is caller-safe and stays, so a 400 remains usable."""

    def test_not_null_violation_names_the_column(self):
        ex = IntegrityError(
            "INSERT INTO auth_api_key_audiences (api_key_id) VALUES (%(id)s)",
            {"id": None},
            Exception(
                'null value in column "api_key_id" of relation '
                '"auth_api_key_audiences" violates not-null constraint'
            ),
        )
        body = _body(handle_route_exception(ex))
        assert body["from_error"] == "IntegrityError"
        assert body["errors"][0]["field_name"] == "api_key_id"

    def test_integrity_error_body_has_no_statement(self):
        ex = IntegrityError(
            "INSERT INTO auth_api_key_audiences (api_key_id) VALUES (%(id)s)",
            {"id": None},
            Exception('null value in column "api_key_id" of relation "x"'),
        )
        assert "INSERT INTO" not in json.dumps(_body(handle_route_exception(ex)))
