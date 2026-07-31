"""Request-bound owner-verifier dependency tests.

The lookup is authorized as the *caller*, not as the service, so the
dependency's whole job is to bind the request's own bearer token to the
directory call — and to bind nothing at all when there is no bearer token.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from fastapi_full.core import deps
from starlette.requests import Request

USER_ID = uuid.UUID("44444444-4444-4444-4444-444444444444")


class _RecordingDirectory:
    """Directory stand-in that records the token it was handed."""

    def __init__(self) -> None:
        self.seen: list[tuple[uuid.UUID, str]] = []

    def user_exists(self, user_id: uuid.UUID, *, bearer_token: str) -> bool:
        self.seen.append((user_id, bearer_token))
        return True


def _request(authorization: Any = None) -> Request:
    headers = [(b"authorization", authorization.encode())] if authorization else []
    return Request({"type": "http", "headers": headers})


class TestBearerToken:
    """Only a bearer scheme yields a token."""

    def test_extracts_a_bearer_token(self) -> None:
        assert deps._bearer_token(_request("Bearer abc.def.ghi")) == "abc.def.ghi"

    def test_is_case_insensitive_on_the_scheme(self) -> None:
        assert deps._bearer_token(_request("bearer abc")) == "abc"

    @pytest.mark.parametrize(
        "header", [None, "Basic dXNlcjpwYXNz", "abc.def.ghi", "Bearer"]
    )
    def test_anything_else_yields_no_token(self, header: Any) -> None:
        assert deps._bearer_token(_request(header)) == ""


class TestGetOwnerVerifier:
    """The returned verifier carries this request's token and nothing else."""

    def test_binds_the_request_token(self, monkeypatch: pytest.MonkeyPatch) -> None:
        directory = _RecordingDirectory()
        monkeypatch.setattr(deps, "user_directory", directory)

        verify = deps.get_owner_verifier(_request("Bearer caller-token"))

        assert verify(USER_ID) is True
        assert directory.seen == [(USER_ID, "caller-token")]

    def test_a_tokenless_request_binds_an_empty_token(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The real directory then fails closed rather than calling the issuer."""
        directory = _RecordingDirectory()
        monkeypatch.setattr(deps, "user_directory", directory)

        deps.get_owner_verifier(_request())(USER_ID)

        assert directory.seen == [(USER_ID, "")]
