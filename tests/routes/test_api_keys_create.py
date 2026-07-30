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
from datetime import datetime, timedelta, timezone
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


def _dead_key(user, *, revoked: bool = False, expires_at=None) -> ApiKey:
    """A key row that is no longer usable — revoked, or past its expiry."""
    return ApiKey(
        id=uuid.uuid4(),
        name=f"dead-{uuid.uuid4().hex[:6]}",
        key_hash=uuid.uuid4().hex + uuid.uuid4().hex,
        user_id=user.id,
        revoked=revoked,
        expires_at=expires_at,
        access_mode=ApiKeyAccessMode.READ_ONLY,
    )


class TestLiveKeyCapAdmitsAReplacement:
    """``APIKEY-LIFECYCLE-01``: the per-user cap bounds *live* credentials.

    ``tests/services/api_keys_test.py::TestCreationCapExcludesExpiredKeys``
    proves the corrected predicate at the query level, but it re-declares that
    predicate inside the test — so it would still pass if the route reverted to
    counting revoked keys only. These call the route itself, which is the thing
    an owner actually hits, so the cap and the route cannot drift apart.
    """

    _CAP = 2

    @pytest.fixture
    def capped(self):
        """Shrink the per-user maximum so the boundary is reachable in a test."""
        with patch(
            "auth_user_service.routes.api_keys.settings.API_KEY_MAX_PER_USER",
            self._CAP,
        ):
            yield

    def test_live_keys_at_the_cap_refuse_a_new_key(
        self, db_session, sample_user, capped
    ):
        for _ in range(self._CAP):
            _create(db_session, sample_user, ttl_hours=24)

        with pytest.raises(HTTPException) as exc_info:
            _create(db_session, sample_user, ttl_hours=24)

        assert exc_info.value.status_code == 409

    def test_expired_keys_at_the_cap_admit_a_replacement(
        self, db_session, sample_user, capped
    ):
        """The regression this correction fixes: an owner whose keys have all
        expired could not issue a replacement without manually revoking corpses."""
        past = datetime.now(timezone.utc) - timedelta(hours=1)
        for _ in range(self._CAP):
            db_session.add(_dead_key(sample_user, expires_at=past))
        db_session.commit()

        created = _create(db_session, sample_user, name="replacement", ttl_hours=24)

        assert created.plaintext.startswith("ak_")
        assert db_session.get(ApiKey, created.id) is not None

    def test_revoked_keys_at_the_cap_admit_a_replacement(
        self, db_session, sample_user, capped
    ):
        for _ in range(self._CAP):
            db_session.add(_dead_key(sample_user, revoked=True))
        db_session.commit()

        created = _create(db_session, sample_user, name="replacement", ttl_hours=24)

        assert db_session.get(ApiKey, created.id) is not None

    def test_another_users_keys_never_consume_this_owners_cap(
        self, db_session, sample_user, superuser, capped
    ):
        for _ in range(self._CAP):
            _create(db_session, superuser, ttl_hours=24)

        created = _create(db_session, sample_user, name="mine", ttl_hours=24)

        assert db_session.get(ApiKey, created.id).user_id == sample_user.id
