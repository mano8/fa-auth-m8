"""Model tests for the normalized ``api_key_audiences`` relation and the
immutable ``ApiKey.access_mode`` cap (§3.11-§3.12, Expand).

These assert the physical contract chosen over a nullable plural column / native
array: a composite-PK relation with an ``ON DELETE CASCADE`` back to the key, and
an ``access_mode`` column defaulting to the most restrictive ``READ_ONLY``.
"""

import uuid

from sqlmodel import select

from auth_sdk_m8.schemas.base import ApiKeyAccessMode
from auth_user_service.db_models.api_keys import ApiKey, ApiKeyAudience


def _make_key(db_session, owner, **attrs) -> ApiKey:
    api_key = ApiKey(
        id=uuid.uuid4(),
        key_hash=(uuid.uuid4().hex + uuid.uuid4().hex),
        user_id=owner.id,
        name="test-key",
        **attrs,
    )
    db_session.add(api_key)
    db_session.commit()
    db_session.refresh(api_key)
    return api_key


class TestAccessModeColumn:
    def test_defaults_to_read_only(self, db_session, sample_user):
        api_key = _make_key(db_session, sample_user)
        assert api_key.access_mode == ApiKeyAccessMode.READ_ONLY

    def test_read_write_persists(self, db_session, sample_user):
        api_key = _make_key(
            db_session, sample_user, access_mode=ApiKeyAccessMode.READ_WRITE
        )
        db_session.expire(api_key)
        assert api_key.access_mode == ApiKeyAccessMode.READ_WRITE


class TestAudienceRelation:
    def test_composite_primary_key(self):
        pk = {c.name for c in ApiKeyAudience.__table__.primary_key.columns}
        assert pk == {"api_key_id", "audience_id"}

    def test_no_audience_rows_by_default(self, db_session, sample_user):
        api_key = _make_key(db_session, sample_user)
        assert list(api_key.audiences) == []

    def test_bind_and_read_back(self, db_session, sample_user):
        api_key = _make_key(db_session, sample_user)
        db_session.add(
            ApiKeyAudience(api_key_id=api_key.id, audience_id="prompt-engine-m8")
        )
        db_session.commit()
        db_session.refresh(api_key)
        assert [a.audience_id for a in api_key.audiences] == ["prompt-engine-m8"]

    def test_cascade_delete_removes_audiences(self, db_session, sample_user):
        api_key = _make_key(db_session, sample_user)
        db_session.add(ApiKeyAudience(api_key_id=api_key.id, audience_id="a-m8"))
        db_session.commit()
        db_session.delete(api_key)
        db_session.commit()
        remaining = db_session.exec(
            select(ApiKeyAudience).where(ApiKeyAudience.api_key_id == api_key.id)
        ).all()
        assert remaining == []
