"""Five-role capability acceptance matrix for the bundled consumer example.

This is the Phase 7 verification surface: it asserts the *decided model* of the
phase — the role/capability table — as an operator experiences it, over the real
routes, through the real ``fastapi-m8`` guards.

Every other module in this suite overrides ``get_current_active_reader`` /
``_writer`` / ``_admin`` / ``_superuser`` with a lambda and therefore proves what
each *handler* does once a principal has been admitted. Nothing there proves that
the right principals are admitted in the first place. This module deliberately
overrides **only** the database session and the issuer owner-lookup, and
authenticates with a genuine HS256 access token minted for the configured
``ACCESS_SECRET_KEY``: the token flows through ``build_auth_deps``' validator,
``UserModel`` validation, ``has_minimum_role`` and the canonical dual-evidence
superuser predicate exactly as it does in a running stack. A guard silently
downgraded to a lower tier — the regression the matrix exists to catch — fails
here and nowhere else.

The matrix (the phase's decided model, categories column):

===========  ======  ===========  ==================  ===============
role         list    read own     write own           other's data
===========  ======  ===========  ==================  ===============
USER         403     403          403                 403
READER       own     200          403                 403
WRITER       own     200          200                 403
ADMIN        own     200          200                 403
SUPERADMIN   all     200          200                 200 + audit row
===========  ======  ===========  ==================  ===============

ADMIN is deliberately *not* widened here: cross-user powers live in other
consumer microservices, so in this example an admin is a writer over its own
data — plus the audit-log read scope, which is the one capability that separates
the two tiers.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Iterator, Optional

import jwt
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlmodel import Session, select

from fastapi_full.app.main import api_router
from fastapi_full.app.ownership import as_owner_id
from fastapi_full.core.config import settings
from fastapi_full.core.deps import get_db, get_owner_verifier
from fastapi_full.core.user_directory import UserDirectoryUnavailable
from fastapi_full.db_models.categories import Category
from fastapi_full.db_models.privileged_action_audit import PrivilegedActionAudit

# Every role in the hierarchy gets its own subject id, so "own data" and
# "someone else's data" are never the same row between two parametrized runs.
ACTOR_IDS: dict[str, uuid.UUID] = {
    "user": uuid.UUID("00000000-0000-0000-0000-0000000000a1"),
    "reader": uuid.UUID("00000000-0000-0000-0000-0000000000a2"),
    "writer": uuid.UUID("00000000-0000-0000-0000-0000000000a3"),
    "admin": uuid.UUID("00000000-0000-0000-0000-0000000000a4"),
    "superadmin": uuid.UUID("00000000-0000-0000-0000-0000000000a5"),
}
OTHER_ID = uuid.UUID("00000000-0000-0000-0000-0000000000ff")

ALL_ROLES = tuple(ACTOR_IDS)
#: Roles whose ``is_superuser`` claim is true — exactly one, by the canonical
#: invariant (a pair outside the truth table does not validate at all).
SUPERUSER_ROLES = frozenset({"superadmin"})

CATEGORY_LIST = "/category/"
AUDIT_LOG = "/security/audit-log"
AUDIT_PURGE = "/security/audit-log/purge"


def access_token(
    role: str,
    *,
    subject: Optional[uuid.UUID] = None,
    is_superuser: Optional[bool] = None,
    is_active: bool = True,
) -> str:
    """Mint a genuine access token for *role*, signed with the app's own key.

    Args:
        role: The ``role`` claim.
        subject: The ``sub`` claim; defaults to the role's fixed actor id.
        is_superuser: The ``is_superuser`` claim; defaults to the canonical
            value for *role*. Pass it explicitly only to forge an inconsistent
            pair on purpose.
        is_active: The ``is_active`` claim.

    Returns:
        The encoded JWT, ready for an ``Authorization: Bearer`` header.
    """
    now = datetime.now(timezone.utc)
    secret = settings.ACCESS_SECRET_KEY
    payload: dict[str, Any] = {
        "sub": str(subject if subject is not None else ACTOR_IDS[role]),
        "jti": uuid.uuid4().hex,
        "type": "access",
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=5)).timestamp()),
        "email": f"{role}@example.com",
        "role": role,
        "is_superuser": (role in SUPERUSER_ROLES)
        if is_superuser is None
        else is_superuser,
        "is_active": is_active,
    }
    return jwt.encode(
        payload,
        secret.get_secret_value(),
        algorithm=settings.ACCESS_TOKEN_ALGORITHM,
    )


def auth(role: str, **kwargs: Any) -> dict[str, str]:
    """Return the ``Authorization`` header carrying a token for *role*."""
    return {"Authorization": f"Bearer {access_token(role, **kwargs)}"}


@pytest.fixture
def client(db_session: Session) -> Iterator[TestClient]:
    """The example's real router table, with only the DB and issuer stubbed.

    The auth guards are **not** overridden: that is the whole point of this
    module. ``get_owner_verifier`` is, because confirming a cross-owner target
    is an HTTP call to the issuer, which no unit test may make.
    """
    app = FastAPI()
    app.include_router(api_router)
    app.dependency_overrides[get_db] = lambda: db_session
    app.dependency_overrides[get_owner_verifier] = lambda: lambda user_id: True
    with TestClient(app) as test_client:
        yield test_client


def category(session: Session, *, owner_id: uuid.UUID, name: str) -> Category:
    """Persist one category owned by *owner_id* and return it."""
    item = Category(name=name, slug=name.lower().replace(" ", "-"), owner_id=owner_id)
    session.add(item)
    session.commit()
    session.refresh(item)
    return item


def audit_rows(session: Session) -> list[PrivilegedActionAudit]:
    """Return every audit row currently persisted."""
    return list(session.exec(select(PrivilegedActionAudit)).all())


@pytest.fixture
def own_and_other(request, db_session: Session) -> tuple[int, int]:
    """One category owned by the role under test, one owned by somebody else."""
    role = request.getfixturevalue("role")
    own = category(db_session, owner_id=ACTOR_IDS[role], name=f"own-{role}")
    other = category(db_session, owner_id=OTHER_ID, name=f"other-{role}")
    return own.id, other.id


@pytest.fixture(params=ALL_ROLES)
def role(request) -> str:
    """Each of the five canonical roles in turn."""
    return request.param


class TestReadCapabilities:
    """Reads: denied outright below READER, owner-scoped up to SUPERADMIN."""

    #: Expected status of ``GET /category/`` per role.
    LIST_STATUS = {
        "user": 403,
        "reader": 200,
        "writer": 200,
        "admin": 200,
        "superadmin": 200,
    }

    def test_list_is_denied_below_reader_and_owner_scoped_above_it(
        self, client, db_session, role, own_and_other
    ) -> None:
        response = client.get(CATEGORY_LIST, headers=auth(role))

        assert response.status_code == self.LIST_STATUS[role]
        if response.status_code != 200:
            return
        body = response.json()
        if role == "superadmin":
            # The only role that sees every user's categories.
            assert body["count"] == 2
        else:
            assert body["count"] == 1
            assert as_owner_id(body["data"][0]["owner_id"]) == ACTOR_IDS[role]

    def test_reading_own_category_needs_reader(
        self, client, db_session, role, own_and_other
    ) -> None:
        own_id, _ = own_and_other

        response = client.get(f"/category/get/{own_id}/", headers=auth(role))

        assert response.status_code == (403 if role == "user" else 200)

    def test_reading_another_users_category_is_superadmin_only(
        self, client, db_session, role, own_and_other
    ) -> None:
        _, other_id = own_and_other

        response = client.get(f"/category/get/{other_id}/", headers=auth(role))

        assert response.status_code == (200 if role == "superadmin" else 403)


class TestWriteCapabilitiesOnOwnedData:
    """Writes on one's own data: WRITER and above, nobody below."""

    #: WRITER is the write threshold; READER and USER are denied by the guard.
    ALLOWED = {"writer", "admin", "superadmin"}

    def test_create_needs_writer(self, client, db_session, role) -> None:
        response = client.post(
            "/category/add/", headers=auth(role), json={"name": f"new-{role}"}
        )

        assert response.status_code == (200 if role in self.ALLOWED else 403)
        persisted = db_session.exec(select(Category)).all()
        if role in self.ALLOWED:
            assert as_owner_id(persisted[0].owner_id) == ACTOR_IDS[role]
        else:
            assert persisted == []

    def test_edit_own_needs_writer(
        self, client, db_session, role, own_and_other
    ) -> None:
        own_id, _ = own_and_other

        response = client.put(
            f"/category/edit/{own_id}/", headers=auth(role), json={"name": "renamed"}
        )

        assert response.status_code == (200 if role in self.ALLOWED else 403)
        item = db_session.get(Category, own_id)
        db_session.refresh(item)
        assert item.name == ("renamed" if role in self.ALLOWED else f"own-{role}")
        # Ownership survives the edit whatever the outcome.
        assert as_owner_id(item.owner_id) == ACTOR_IDS[role]

    def test_delete_own_needs_writer(
        self, client, db_session, role, own_and_other
    ) -> None:
        own_id, _ = own_and_other

        response = client.delete(f"/category/delete/{own_id}/", headers=auth(role))

        assert response.status_code == (200 if role in self.ALLOWED else 403)
        assert (db_session.get(Category, own_id) is None) is (role in self.ALLOWED)

    def test_no_role_writes_an_audit_row_for_its_own_data(
        self, client, db_session, role, own_and_other
    ) -> None:
        """Ordinary work on one's own data is never a privileged action."""
        own_id, _ = own_and_other

        client.post("/category/add/", headers=auth(role), json={"name": f"n-{role}"})
        client.put(
            f"/category/edit/{own_id}/", headers=auth(role), json={"name": "renamed"}
        )
        client.delete(f"/category/delete/{own_id}/", headers=auth(role))

        assert audit_rows(db_session) == []


class TestCrossOwnerCapabilities:
    """Another user's data: SUPERADMIN only, and always audited."""

    def test_edit_of_another_users_category_is_superadmin_only(
        self, client, db_session, role, own_and_other
    ) -> None:
        _, other_id = own_and_other

        response = client.put(
            f"/category/edit/{other_id}/", headers=auth(role), json={"name": "seized"}
        )

        assert response.status_code == (200 if role == "superadmin" else 403)
        item = db_session.get(Category, other_id)
        db_session.refresh(item)
        # The owner is never rewritten to the actor, allowed or refused.
        assert as_owner_id(item.owner_id) == OTHER_ID
        assert item.name == ("seized" if role == "superadmin" else f"other-{role}")

    def test_delete_of_another_users_category_is_superadmin_only(
        self, client, db_session, role, own_and_other
    ) -> None:
        _, other_id = own_and_other

        response = client.delete(f"/category/delete/{other_id}/", headers=auth(role))

        assert response.status_code == (200 if role == "superadmin" else 403)
        assert (db_session.get(Category, other_id) is None) is (role == "superadmin")

    def test_create_on_behalf_of_another_user_is_superadmin_only(
        self, client, db_session, role
    ) -> None:
        response = client.post(
            "/category/add/",
            headers=auth(role),
            json={"name": f"gift-{role}", "target_owner_id": str(OTHER_ID)},
        )

        assert response.status_code == (200 if role == "superadmin" else 403)
        persisted = db_session.exec(select(Category)).all()
        if role == "superadmin":
            assert as_owner_id(persisted[0].owner_id) == OTHER_ID
        else:
            # Refused — and never silently re-homed to the actor.
            assert persisted == []

    @pytest.mark.parametrize("action", ["add", "edit", "delete"])
    def test_each_superadmin_cross_owner_mutation_writes_exactly_one_row(
        self, client, db_session, action: str
    ) -> None:
        headers = auth("superadmin")
        item = category(db_session, owner_id=OTHER_ID, name="theirs")

        if action == "add":
            client.post(
                "/category/add/",
                headers=headers,
                json={"name": "gift", "target_owner_id": str(OTHER_ID)},
            )
        elif action == "edit":
            client.put(
                f"/category/edit/{item.id}/", headers=headers, json={"name": "seized"}
            )
        else:
            client.delete(f"/category/delete/{item.id}/", headers=headers)

        rows = audit_rows(db_session)
        assert len(rows) == 1
        assert rows[0].action.value == action
        assert rows[0].actor_user_id == ACTOR_IDS["superadmin"]
        assert rows[0].actor_role == "superadmin"
        assert rows[0].target_owner_id == str(OTHER_ID)


class TestAuditReadScope:
    """admin-own vs superadmin-all vs 403, through the real ADMIN-tier guard."""

    def _seed(self, session: Session) -> None:
        session.add(
            PrivilegedActionAudit(
                actor_user_id=ACTOR_IDS["superadmin"],
                actor_role="superadmin",
                action="edit",
                table_name=str(Category.__tablename__),
                row_pk="1",
                target_owner_id=str(OTHER_ID),
            )
        )
        session.commit()

    @pytest.mark.parametrize("denied_role", ["user", "reader", "writer"])
    def test_below_admin_is_denied(self, client, db_session, denied_role) -> None:
        self._seed(db_session)

        assert client.get(AUDIT_LOG, headers=auth(denied_role)).status_code == 403

    def test_admin_sees_only_rows_it_authored(self, client, db_session) -> None:
        """Only a superadmin can mutate non-owned data here, so an admin's own
        view is legitimately empty — the filter is proven by the superadmin
        row below being invisible to it, not by an empty table."""
        self._seed(db_session)

        body = client.get(AUDIT_LOG, headers=auth("admin")).json()

        assert body == {"data": [], "count": 0}

    def test_superadmin_sees_every_row(self, client, db_session) -> None:
        self._seed(db_session)

        body = client.get(AUDIT_LOG, headers=auth("superadmin")).json()

        assert body["count"] == 1
        assert body["data"][0]["actor_user_id"] == str(ACTOR_IDS["superadmin"])

    @pytest.mark.parametrize("denied_role", ["user", "reader", "writer", "admin"])
    def test_the_purge_is_superadmin_only(self, client, denied_role) -> None:
        """The audit table's only removal path stops at the superuser tier —
        an ADMIN that may *read* its own rows may not purge anything."""
        response = client.post(
            AUDIT_PURGE, headers=auth(denied_role), json={"window": "1y"}
        )

        assert response.status_code == 403


class TestOwnershipPreservationOverTheWire:
    """G7-5 as an operator meets it: ownership is never client-settable."""

    def test_owner_id_in_a_create_body_is_rejected(self, client, db_session) -> None:
        response = client.post(
            "/category/add/",
            headers=auth("superadmin"),
            json={"name": "smuggled", "owner_id": str(OTHER_ID)},
        )

        assert response.status_code == 422
        assert db_session.exec(select(Category)).all() == []

    def test_owner_id_in_an_edit_body_is_rejected(self, client, db_session) -> None:
        item = category(db_session, owner_id=OTHER_ID, name="theirs")

        response = client.put(
            f"/category/edit/{item.id}/",
            headers=auth("superadmin"),
            json={"name": "seized", "owner_id": str(ACTOR_IDS["superadmin"])},
        )

        assert response.status_code == 422
        db_session.refresh(item)
        assert as_owner_id(item.owner_id) == OTHER_ID

    def test_target_owner_id_in_an_edit_body_is_rejected(
        self, client, db_session
    ) -> None:
        item = category(db_session, owner_id=OTHER_ID, name="theirs")

        response = client.put(
            f"/category/edit/{item.id}/",
            headers=auth("superadmin"),
            json={"name": "seized", "target_owner_id": str(ACTOR_IDS["superadmin"])},
        )

        assert response.status_code == 422
        db_session.refresh(item)
        assert as_owner_id(item.owner_id) == OTHER_ID

    def test_unknown_target_owner_is_404_and_persists_nothing(
        self, client, db_session
    ) -> None:
        client.app.dependency_overrides[get_owner_verifier] = lambda: (
            lambda user_id: False
        )

        response = client.post(
            "/category/add/",
            headers=auth("superadmin"),
            json={"name": "orphan", "target_owner_id": str(OTHER_ID)},
        )

        assert response.status_code == 404
        assert db_session.exec(select(Category)).all() == []
        assert audit_rows(db_session) == []

    def test_unverifiable_target_owner_is_503_and_persists_nothing(
        self, client, db_session
    ) -> None:
        def _unavailable(user_id):
            raise UserDirectoryUnavailable("issuer_unreachable")

        client.app.dependency_overrides[get_owner_verifier] = lambda: _unavailable

        response = client.post(
            "/category/add/",
            headers=auth("superadmin"),
            json={"name": "orphan", "target_owner_id": str(OTHER_ID)},
        )

        assert response.status_code == 503
        assert db_session.exec(select(Category)).all() == []
        assert audit_rows(db_session) == []

    def test_a_superadmin_naming_itself_owns_its_own_row(
        self, client, db_session
    ) -> None:
        """``target_owner_id == actor`` is a self-owned create, not a privileged
        one: the row belongs to the actor and nothing is audited."""
        response = client.post(
            "/category/add/",
            headers=auth("superadmin"),
            json={"name": "mine", "target_owner_id": str(ACTOR_IDS["superadmin"])},
        )

        assert response.status_code == 200
        item = db_session.exec(select(Category)).one()
        assert as_owner_id(item.owner_id) == ACTOR_IDS["superadmin"]
        assert audit_rows(db_session) == []


class TestClaimsCannotBypassTheMatrix:
    """The guards read the role, and only a consistent claim pair is admitted."""

    @pytest.mark.parametrize("stray_role", ["user", "reader", "writer", "admin"])
    def test_a_stray_superuser_flag_never_widens_a_role(
        self, client, db_session, stray_role
    ) -> None:
        """A token claiming ``is_superuser`` on a lower role is refused before
        any handler runs — the pair is outside the canonical truth table, so it
        fails validation rather than granting the flag's privileges."""
        item = category(db_session, owner_id=OTHER_ID, name="theirs")
        headers = auth(stray_role, is_superuser=True)

        assert client.get(CATEGORY_LIST, headers=headers).status_code == 403
        assert (
            client.get(f"/category/get/{item.id}/", headers=headers).status_code == 403
        )

    def test_a_superadmin_without_the_flag_is_not_a_canonical_superuser(
        self, client, db_session
    ) -> None:
        """``role=superadmin`` with ``is_superuser=false`` is likewise outside
        the truth table: the dual-evidence predicate has no half-satisfied
        state to exploit."""
        item = category(db_session, owner_id=OTHER_ID, name="theirs")

        response = client.get(
            f"/category/get/{item.id}/",
            headers=auth("superadmin", is_superuser=False),
        )

        assert response.status_code == 403

    def test_an_inactive_principal_is_denied_at_every_tier(
        self, client, db_session, role
    ) -> None:
        response = client.get(CATEGORY_LIST, headers=auth(role, is_active=False))

        assert response.status_code == 403

    def test_an_unauthenticated_request_never_reaches_a_handler(
        self, client, db_session
    ) -> None:
        item = category(db_session, owner_id=OTHER_ID, name="theirs")

        assert client.get(CATEGORY_LIST).status_code == 401
        assert client.post("/category/add/", json={"name": "x"}).status_code == 401
        assert client.delete(f"/category/delete/{item.id}/").status_code == 401
        assert client.get(AUDIT_LOG).status_code == 401
