"""Phase 7 secret non-exposure invariant — every read surface, proven twice.

The invariant (Phase 7, *Secret non-exposure*): no admin/superadmin read
surface may return another user's secrets — never a password hash, never API-key
material (raw or hashed), never a refresh-token hash or an encrypted external
OAuth token. API-key listings are metadata only; the raw key is shown once to
its owner at creation and never again.

Individual surfaces already assert their own exact field sets
(``tests/routes/test_api_keys_admin.py``,
``tests/db_models/test_api_key_audiences.py``). What was missing — and what this
module adds — is the invariant stated *once, over the whole route table*, so a
new route, a widened response model, or a `response_model` swapped back to a
table model fails here without anyone remembering to extend a per-route test.

Two independent proofs, because either alone can be defeated:

1. **Structural** — walk every route the live app registers, recurse through its
   declared ``response_model`` (including nested models and containers), and
   reject any field whose name carries secret material. Exactly one exception is
   allowlisted, with the reason recorded next to it.
2. **Behavioural** — build real rows carrying distinctive secret values, project
   them through the very models the routes declare, and assert those values
   appear nowhere in the serialized JSON. A field renamed around the structural
   pattern is still caught here.
"""

from __future__ import annotations

import re
import types
import typing
import uuid
from collections.abc import Iterable, Iterator
from datetime import datetime, timedelta, timezone

from fastapi.routing import APIRoute
from pydantic import BaseModel
from starlette.routing import BaseRoute

from auth_sdk_m8.schemas.base import ApiKeyAccessMode, AuthProviderType, RoleType

from auth_user_service.db_models.api_keys import (
    ApiKey,
    ApiKeyAdminPublic,
    ApiKeyPublic,
    ApiKeysAdminPublic,
)
from auth_user_service.db_models.sessions import (
    ClientSession,
    ClientSessionPublic,
    ClientSessionsPublic,
)
from auth_user_service.db_models.users import (
    User,
    UserAuthorizationUpdate,
    UserPublic,
    UsersPublic,
)
from auth_user_service.main import app
from auth_user_service.schemas.user import ResponseUser

#: A field name matching this pattern carries (or plausibly carries) secret
#: material. Deliberately broader than the columns that exist today, so a future
#: ``password_reset_hash`` or ``client_secret`` is caught the day it is added.
_SECRET_FIELD_PATTERN = re.compile(
    r"password|hash|secret|private_key|plaintext|raw_key", re.IGNORECASE
)

#: The one documented exception: the raw API key is returned exactly once, to
#: its own owner, in the 201 creation response, and is never stored or readable
#: again (§3.11). Every other surface — including the superadmin listing — is
#: metadata only. Keyed by ``(model name, field name)`` so widening the model
#: with a second secret field still fails.
_ALLOWED_SECRET_FIELDS: frozenset[tuple[str, str]] = frozenset(
    {("ApiKeyCreated", "plaintext")}
)

#: Distinctive values planted in the rows below; none may survive serialization.
_PASSWORD_HASH = "$2b$12$SecretPasswordHashMustNeverBeSerialised0000000000000"
_KEY_HASH = "a1secretkeyhashvaluethatmustnotleak" + "b" * 32
_REFRESH_HASH = "c2secretrefreshtokenhashthatmustnotleak" + "d" * 32
_EXTERNAL_ACCESS = "e3-secret-google-access-token-must-not-leak"
_EXTERNAL_REFRESH = "f4-secret-google-refresh-token-must-not-leak"


def _iter_api_routes(routes: Iterable[BaseRoute]) -> Iterator[APIRoute]:
    """Yield every ``APIRoute`` the app registers, through lazy inclusion.

    FastAPI >= 0.137 no longer flattens ``include_router`` into ``app.routes``;
    it inserts an opaque ``_IncludedRouter``. Descend through both shapes, the
    same way ``tests/security/test_route_inventory.py`` does, so this invariant
    cannot be dodged by a router nesting depth.
    """
    for route in routes:
        if isinstance(route, APIRoute):
            yield route
        elif type(route).__name__ == "_IncludedRouter":
            original = getattr(route, "original_router", None)
            yield from _iter_api_routes(getattr(original, "routes", []))
        elif hasattr(route, "routes"):
            yield from _iter_api_routes(getattr(route, "routes", []))


def _iter_models(annotation: object, seen: set[type]) -> Iterator[type[BaseModel]]:
    """Yield every Pydantic model reachable from *annotation*.

    Unwraps ``Optional``/unions, containers, and nested model fields, so a
    wrapper such as ``UsersPublic`` is inspected together with the
    ``UserPublic`` rows it carries.
    """
    if isinstance(annotation, type) and issubclass(annotation, BaseModel):
        if annotation in seen:
            return
        seen.add(annotation)
        yield annotation
        for field in annotation.model_fields.values():
            yield from _iter_models(field.annotation, seen)
        return
    if isinstance(annotation, (types.UnionType, type(typing.Optional[int]))) or (
        typing.get_origin(annotation) is not None
    ):
        for argument in typing.get_args(annotation):
            yield from _iter_models(argument, seen)


def _secret_fields_of(model: type[BaseModel]) -> set[tuple[str, str]]:
    """Return ``(model name, field name)`` for every secret-looking field."""
    return {
        (model.__name__, name)
        for name in model.model_fields
        if _SECRET_FIELD_PATTERN.search(name)
    }


def _response_model_secret_fields() -> set[tuple[str, str]]:
    """Every secret-looking field reachable from any declared response model."""
    found: set[tuple[str, str]] = set()
    for route in _iter_api_routes(app.routes):
        seen: set[type] = set()
        for model in _iter_models(route.response_model, seen):
            found |= _secret_fields_of(model)
    return found


def _user_row() -> User:
    return User(
        id=uuid.uuid4(),
        email="target@example.com",
        full_name="Target User",
        hashed_password=_PASSWORD_HASH,
        provider=AuthProviderType.PASSWORD,
        is_active=True,
        email_verified=True,
        is_superuser=False,
        role=RoleType.USER,
    )


def _session_row(user_id: uuid.UUID) -> ClientSession:
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    return ClientSession(
        id=str(uuid.uuid4()),
        user_id=user_id,
        provider=AuthProviderType.GOOGLE,
        jwt_jti=str(uuid.uuid4()),
        refresh_token_hash=_REFRESH_HASH,
        jwt_expires_at=now + timedelta(hours=1),
        refresh_expires_at=now + timedelta(days=7),
        external_access_token=_EXTERNAL_ACCESS,
        external_refresh_token=_EXTERNAL_REFRESH,
        external_token_expires_at=now + timedelta(hours=1),
        revoked=False,
    )


def _api_key_row(user_id: uuid.UUID) -> ApiKey:
    """An unpersisted key row; ``id``/``created_at`` are DB-side defaults."""
    return ApiKey(
        id=uuid.uuid4(),
        name="ci-key",
        key_hash=_KEY_HASH,
        user_id=user_id,
        created_at=datetime.now(timezone.utc),
        access_mode=ApiKeyAccessMode.READ_ONLY,
    )


class TestNoRouteDeclaresASecretBearingResponse:
    """Structural proof, stated once over the whole live route table."""

    def test_only_the_allowlisted_creation_response_carries_key_material(
        self,
    ) -> None:
        assert _response_model_secret_fields() == _ALLOWED_SECRET_FIELDS

    def test_the_allowlist_is_exactly_the_one_documented_exception(self) -> None:
        """A second entry must not be added silently: the raw key is shown once,
        to its owner, at creation — that is the whole exception."""
        assert len(_ALLOWED_SECRET_FIELDS) == 1

    def test_the_walk_descends_into_nested_and_contained_models(self) -> None:
        """Negative control: the invariant above is only as wide as this walk.

        A listing declares the wrapper, and the rows it carries are what would
        leak, so the wrapper alone is not enough.
        """
        reachable = {model.__name__ for model in _iter_models(UsersPublic, set())}

        assert {"UsersPublic", "UserPublic"} <= reachable

    def test_the_pattern_would_catch_a_reintroduced_secret_column(self) -> None:
        """Negative control: the structural test above is only meaningful if the
        pattern actually rejects the columns this invariant exists to keep out."""
        assert _secret_fields_of(User) >= {("User", "hashed_password")}
        assert _secret_fields_of(ClientSession) >= {
            ("ClientSession", "refresh_token_hash")
        }
        assert _secret_fields_of(ApiKey) >= {("ApiKey", "key_hash")}

    def test_no_route_returns_a_table_model_directly(self) -> None:
        """A ``response_model`` swapped back to the ORM row would serialise every
        column, including the ones above — so no route may declare one.

        The test is ``__table__``, not ``__tablename__``: SQLModel gives every
        subclass a default ``__tablename__``, so only the mapped class carries a
        ``__table__``.
        """
        offenders = set()
        for route in _iter_api_routes(app.routes):
            seen: set[type] = set()
            for model in _iter_models(route.response_model, seen):
                if getattr(model, "__table__", None) is not None:
                    offenders.add((route.path, model.__name__))
        assert offenders == set()

    def test_the_table_model_check_would_catch_a_mapped_class(self) -> None:
        """Negative control for the check above."""
        assert getattr(User, "__table__", None) is not None
        assert getattr(UserPublic, "__table__", None) is None


class TestUserReadSurfacesNeverSerialiseThePasswordHash:
    """A superadmin reading any user gets the profile, never the credential."""

    def test_single_user_view(self) -> None:
        dumped = UserPublic.model_validate(_user_row(), from_attributes=True)

        assert "hashed_password" not in dumped.model_dump()
        assert _PASSWORD_HASH not in dumped.model_dump_json()

    def test_paginated_listing(self) -> None:
        payload = UsersPublic(data=[_user_row(), _user_row()], count=2)

        assert _PASSWORD_HASH not in payload.model_dump_json()

    def test_role_change_response(self) -> None:
        """``PATCH /users/update/{user_id}/`` — the widest user response there
        is, since it adds the generation and revocation contract fields."""
        user = _user_row()
        payload = UserAuthorizationUpdate.model_validate(
            {
                **UserPublic.model_validate(user, from_attributes=True).model_dump(),
                "auth_generation": 2,
                "revocation_enqueued": True,
            }
        )

        assert "hashed_password" not in payload.model_dump()
        assert _PASSWORD_HASH not in payload.model_dump_json()

    def test_profile_update_response(self) -> None:
        payload = ResponseUser(
            success=True,
            user=UserPublic.model_validate(_user_row(), from_attributes=True),
        )

        assert _PASSWORD_HASH not in payload.model_dump_json()


class TestSessionReadSurfacesNeverSerialiseTokenMaterial:
    """Session listings carry metadata and expiries — never the tokens."""

    def test_single_session_view(self) -> None:
        row = _session_row(uuid.uuid4())

        dumped = ClientSessionPublic.model_validate(
            row, from_attributes=True
        ).model_dump_json()

        assert _REFRESH_HASH not in dumped
        assert _EXTERNAL_ACCESS not in dumped
        assert _EXTERNAL_REFRESH not in dumped

    def test_paginated_listing(self) -> None:
        user_id = uuid.uuid4()
        payload = ClientSessionsPublic(
            data=[
                ClientSessionPublic.model_validate(
                    _session_row(user_id), from_attributes=True
                )
            ],
            count=1,
        )

        dumped = payload.model_dump_json()
        assert _REFRESH_HASH not in dumped
        assert _EXTERNAL_ACCESS not in dumped
        assert _EXTERNAL_REFRESH not in dumped

    def test_the_expiry_is_still_exposed(self) -> None:
        """Negative control: the tokens are gone but the session is still
        usable metadata, so the test above is not passing on an empty payload."""
        row = _session_row(uuid.uuid4())

        dumped = ClientSessionPublic.model_validate(row, from_attributes=True)

        assert dumped.external_token_expires_at is not None
        assert dumped.jwt_jti == row.jwt_jti


class TestApiKeyReadSurfacesNeverSerialiseKeyMaterial:
    """Owner view and superadmin view alike: metadata only (§3.11/§3.12)."""

    def test_owner_view(self) -> None:
        dumped = ApiKeyPublic.from_key(_api_key_row(uuid.uuid4()))

        assert "key_hash" not in dumped.model_dump()
        assert _KEY_HASH not in dumped.model_dump_json()

    def test_superadmin_view(self) -> None:
        dumped = ApiKeyAdminPublic.from_key(_api_key_row(uuid.uuid4()))

        assert "key_hash" not in dumped.model_dump()
        assert _KEY_HASH not in dumped.model_dump_json()

    def test_superadmin_listing(self) -> None:
        user_id = uuid.uuid4()
        payload = ApiKeysAdminPublic(
            data=[ApiKeyAdminPublic.from_key(_api_key_row(user_id))], count=1
        )

        assert _KEY_HASH not in payload.model_dump_json()

    def test_the_superadmin_view_cannot_inherit_the_secret_column(self) -> None:
        """The invariant is structural here: ``ApiKeyAdminPublic`` does not
        derive from ``ApiKey``, so there is no column to omit by accident."""
        assert not issubclass(ApiKeyAdminPublic, ApiKey)
        assert "key_hash" not in ApiKeyAdminPublic.model_fields
