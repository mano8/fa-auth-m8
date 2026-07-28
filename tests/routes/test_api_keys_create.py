"""Owner API-key issuance with audiences (``POST /profile/api-keys/``, §3.12).

The reported failure: issuing a key with an ``audiences`` list answered 400
with ``Field 'api_key_id' cannot be null``. A new key's primary key is applied
at INSERT time, so the bindings were built from an id that did not exist yet
and were written with a null foreign key. Nothing under
``examples/``-free unit coverage exercised the creation route with audiences,
which is why it shipped.

The route is called directly with fixtures, matching the ``test_api_keys_admin``
style.
"""

import uuid
from unittest.mock import patch

import pytest
from fastapi import HTTPException
from sqlmodel import select

from auth_sdk_m8.schemas.base import ApiKeyAccessMode
from auth_user_service.db_models.api_keys import ApiKey, ApiKeyAudience, ApiKeyCreate
from auth_user_service.routes.api_keys import create_api_key

_PERMITTED = frozenset({"example-api", "prompt-engine-m8"})


@pytest.fixture
def permitted_audiences():
    """Register the consumers a key is allowed to name."""
    with patch(
        "auth_user_service.core.consumer_registry.get_introspection_audiences",
        return_value=_PERMITTED,
    ):
        yield


def _create(db_session, user, **body):
    return create_api_key(
        session=db_session,
        current_user=user,
        body=ApiKeyCreate(**body),
    )


class TestCreateWithAudiences:
    """The key row and its bindings commit together, with a real foreign key."""

    def test_key_is_issued(self, db_session, sample_user, permitted_audiences):
        created = _create(
            db_session,
            sample_user,
            name="test_user_a1",
            ttl_hours=24,
            access_mode=ApiKeyAccessMode.READ_ONLY,
            audiences=["example-api"],
        )
        assert created.plaintext.startswith("ak_")
        assert created.audiences == ["example-api"]

    def test_bindings_carry_the_new_keys_id(
        self, db_session, sample_user, permitted_audiences
    ):
        """The regression: these rows used to be written with a null key id."""
        created = _create(
            db_session, sample_user, name="bound-key", audiences=["example-api"]
        )
        rows = db_session.exec(
            select(ApiKeyAudience).where(ApiKeyAudience.api_key_id == created.id)
        ).all()
        assert [row.audience_id for row in rows] == ["example-api"]
        assert all(row.api_key_id is not None for row in rows)

    def test_multiple_audiences_all_bind(
        self, db_session, sample_user, permitted_audiences
    ):
        created = _create(
            db_session,
            sample_user,
            name="multi-key",
            audiences=["example-api", "prompt-engine-m8"],
        )
        key = db_session.get(ApiKey, created.id)
        assert sorted(a.audience_id for a in key.audiences) == [
            "example-api",
            "prompt-engine-m8",
        ]

    def test_key_without_audiences_is_issuer_local(self, db_session, sample_user):
        """The security-first default: no bindings, so no remote introspection."""
        created = _create(db_session, sample_user, name="local-key")
        assert created.audiences == []
        assert db_session.get(ApiKey, created.id).audiences == []


class TestCreateRefusals:
    """An unauthorized audience never leaves a persisted key behind."""

    def test_ineligible_audience_is_refused(
        self, db_session, sample_user, permitted_audiences
    ):
        with pytest.raises(HTTPException) as exc_info:
            _create(
                db_session,
                sample_user,
                name="bad-key",
                audiences=[f"not-a-consumer-{uuid.uuid4().hex[:6]}"],
            )
        assert exc_info.value.status_code == 409

    def test_a_refused_request_persists_nothing(
        self, db_session, sample_user, permitted_audiences
    ):
        before = len(
            db_session.exec(
                select(ApiKey).where(ApiKey.user_id == sample_user.id)
            ).all()
        )
        with pytest.raises(HTTPException):
            _create(
                db_session, sample_user, name="bad-key", audiences=["not-a-consumer"]
            )
        after = len(
            db_session.exec(
                select(ApiKey).where(ApiKey.user_id == sample_user.id)
            ).all()
        )
        assert after == before
