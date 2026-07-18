"""Unit tests for the RevocationOutbox model (db_models.outbox).

Focuses on the DB-level invariant that makes duplicate enqueue/drain harmless:
the unique constraint on ``(user_id, auth_generation, effect_type,
target_digest)`` (3.5.2).
"""

import uuid

import pytest
from sqlalchemy.exc import IntegrityError

from auth_user_service.db_models.outbox import (
    EFFECT_BLACKLIST,
    STATUS_PENDING,
    RevocationOutbox,
)


def _row(user_id, digest="d1") -> RevocationOutbox:
    return RevocationOutbox(
        user_id=user_id,
        auth_generation=1,
        effect_type=EFFECT_BLACKLIST,
        target_digest=digest,
        payload={"jti": "x", "expires_at": "2099-01-01T00:00:00+00:00"},
        status=STATUS_PENDING,
    )


class TestUniqueConstraint:
    def test_duplicate_effect_target_rejected(self, db_session):
        uid = uuid.uuid4()
        db_session.add(_row(uid))
        db_session.commit()

        db_session.add(_row(uid))
        with pytest.raises(IntegrityError):
            db_session.commit()
        db_session.rollback()

    def test_distinct_digests_allowed(self, db_session):
        uid = uuid.uuid4()
        db_session.add(_row(uid, digest="a"))
        db_session.add(_row(uid, digest="b"))
        db_session.commit()  # no error — different target_digest
