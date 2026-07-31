"""Ownership preservation tests (Phase 7, G7-5).

The single property every test here defends: **the actor's id is never
substituted for the owner**. A create owns to the actor only when the actor is
the intended owner; every other outcome either persists the exact requested
owner or refuses outright, and no edit or delete rewrites an existing one.
"""

from __future__ import annotations

import uuid
from typing import Any, Optional

import pytest
from fastapi_full.app.ownership import (
    CrossOwnerForbidden,
    OwnershipError,
    OwnerVerificationUnavailable,
    TargetOwnerNotFound,
    as_owner_id,
    category_update_values,
    is_canonical_superuser,
    is_owned_by,
    resolve_create_owner_id,
)
from fastapi_full.core.user_directory import UserDirectoryUnavailable
from fastapi_full.db_models.categories import (
    CategoryCreate,
    CategoryUpdate,
    build_category,
)
from fastapi_m8 import UserModel
from pydantic import ValidationError

ACTOR_ID = uuid.UUID("11111111-1111-1111-1111-111111111111")
TARGET_ID = uuid.UUID("22222222-2222-2222-2222-222222222222")


def _user(role: str, is_superuser: bool) -> UserModel:
    """Build an authenticated principal with a canonical claim pair."""
    return UserModel(
        id=ACTOR_ID,
        email="actor@example.com",
        role=role,  # type: ignore[arg-type]
        is_superuser=is_superuser,
    )


class _RecordingVerifier:
    """Owner verifier that records its calls and returns a fixed answer."""

    def __init__(self, exists: bool) -> None:
        self.exists = exists
        self.calls: list[uuid.UUID] = []

    def __call__(self, user_id: uuid.UUID) -> bool:
        self.calls.append(user_id)
        return self.exists


def _unavailable_verifier(user_id: uuid.UUID) -> bool:
    """Owner verifier standing in for an unreachable issuer."""
    raise UserDirectoryUnavailable("user_directory_transport")


class TestOwnerIdIsNeverBodySettable:
    """``owner_id`` is rejected by the schemas, not silently ignored."""

    def test_create_rejects_owner_id_in_body(self) -> None:
        with pytest.raises(ValidationError) as exc_info:
            CategoryCreate.model_validate({"name": "News", "owner_id": str(TARGET_ID)})
        assert exc_info.value.errors()[0]["type"] == "extra_forbidden"

    def test_update_rejects_owner_id_in_body(self) -> None:
        with pytest.raises(ValidationError) as exc_info:
            CategoryUpdate.model_validate({"name": "News", "owner_id": str(TARGET_ID)})
        assert exc_info.value.errors()[0]["type"] == "extra_forbidden"

    def test_update_rejects_target_owner_id_in_body(self) -> None:
        """An edit never re-homes a row, so it takes no ownership field at all."""
        with pytest.raises(ValidationError) as exc_info:
            CategoryUpdate.model_validate(
                {"name": "News", "target_owner_id": str(TARGET_ID)}
            )
        assert exc_info.value.errors()[0]["type"] == "extra_forbidden"

    def test_create_accepts_the_explicit_cross_owner_field(self) -> None:
        item_in = CategoryCreate.model_validate(
            {"name": "News", "target_owner_id": str(TARGET_ID)}
        )
        assert item_in.target_owner_id == TARGET_ID

    def test_create_defaults_to_no_cross_owner_request(self) -> None:
        assert CategoryCreate(name="News").target_owner_id is None


class TestBuildCategory:
    """The persisted owner comes from the resolved argument and nowhere else."""

    def test_owner_comes_from_the_argument(self) -> None:
        item_in = CategoryCreate(name="News")
        item = build_category(item_in, owner_id=TARGET_ID)
        assert item.owner_id == TARGET_ID
        assert item.name == "News"
        assert item.slug == "news"

    def test_target_owner_id_is_an_input_never_a_persisted_value(self) -> None:
        """A body's ``target_owner_id`` does not leak past the ownership rules."""
        item_in = CategoryCreate.model_validate(
            {"name": "News", "target_owner_id": str(TARGET_ID)}
        )
        item = build_category(item_in, owner_id=ACTOR_ID)
        assert item.owner_id == ACTOR_ID
        assert not hasattr(item, "target_owner_id")


class TestCategoryUpdateValues:
    """An edit writes content fields only."""

    def test_content_fields_survive(self) -> None:
        values = category_update_values(CategoryUpdate(name="Sports"))
        assert values == {"name": "Sports", "slug": "sports"}

    def test_ownership_keys_are_stripped(self) -> None:
        """Defence in depth for a programmatic caller that bypasses the schema."""

        class _LeakyUpdate(CategoryUpdate):
            def model_dump(self, **kwargs: Any) -> dict[str, Any]:
                values: dict[str, Any] = super().model_dump(**kwargs)
                values["owner_id"] = ACTOR_ID
                values["target_owner_id"] = ACTOR_ID
                return values

        values = category_update_values(_LeakyUpdate(name="Sports"))
        assert "owner_id" not in values
        assert "target_owner_id" not in values
        assert values == {"name": "Sports", "slug": "sports"}


class TestIsCanonicalSuperuser:
    """Only the consistent dual-evidence pair counts as a superuser."""

    def test_canonical_superuser(self) -> None:
        assert is_canonical_superuser(_user("superadmin", True)) is True

    @pytest.mark.parametrize("role", ["user", "reader", "writer", "admin"])
    def test_lesser_roles_are_not_superusers(self, role: str) -> None:
        assert is_canonical_superuser(_user(role, False)) is False


class TestOwnerIdNormalisation:
    """``owner_id`` is a raw ``CHAR(36)``: a loaded row carries it as text."""

    def test_uuid_passes_through(self) -> None:
        assert as_owner_id(ACTOR_ID) == ACTOR_ID

    def test_text_form_is_normalised(self) -> None:
        assert as_owner_id(str(ACTOR_ID)) == ACTOR_ID

    def test_persisted_text_owner_matches_the_principals_uuid_id(self) -> None:
        """Without the normalisation an owner would be denied on their own row."""
        assert is_owned_by(str(ACTOR_ID), ACTOR_ID) is True

    def test_a_different_owner_never_matches(self) -> None:
        assert is_owned_by(str(TARGET_ID), ACTOR_ID) is False


class TestResolveCreateOwnerId:
    """The create path resolves exactly one owner, or refuses."""

    def test_no_target_owns_to_the_actor(self) -> None:
        verifier = _RecordingVerifier(exists=True)
        owner_id = resolve_create_owner_id(
            actor_id=ACTOR_ID,
            actor_is_canonical_superuser=False,
            target_owner_id=None,
            verify_owner_exists=verifier,
        )
        assert owner_id == ACTOR_ID
        assert verifier.calls == []

    def test_target_equal_to_actor_needs_no_lookup(self) -> None:
        verifier = _RecordingVerifier(exists=True)
        owner_id = resolve_create_owner_id(
            actor_id=ACTOR_ID,
            actor_is_canonical_superuser=False,
            target_owner_id=ACTOR_ID,
            verify_owner_exists=verifier,
        )
        assert owner_id == ACTOR_ID
        assert verifier.calls == []

    def test_superuser_cross_owner_returns_the_target(self) -> None:
        verifier = _RecordingVerifier(exists=True)
        owner_id = resolve_create_owner_id(
            actor_id=ACTOR_ID,
            actor_is_canonical_superuser=True,
            target_owner_id=TARGET_ID,
            verify_owner_exists=verifier,
        )
        assert owner_id == TARGET_ID
        assert owner_id != ACTOR_ID
        assert verifier.calls == [TARGET_ID]

    def test_non_superuser_cross_owner_is_forbidden_without_a_lookup(self) -> None:
        verifier = _RecordingVerifier(exists=True)
        with pytest.raises(CrossOwnerForbidden) as exc_info:
            resolve_create_owner_id(
                actor_id=ACTOR_ID,
                actor_is_canonical_superuser=False,
                target_owner_id=TARGET_ID,
                verify_owner_exists=verifier,
            )
        assert exc_info.value.status_code == 403
        assert verifier.calls == []

    def test_unknown_target_is_not_found(self) -> None:
        with pytest.raises(TargetOwnerNotFound) as exc_info:
            resolve_create_owner_id(
                actor_id=ACTOR_ID,
                actor_is_canonical_superuser=True,
                target_owner_id=TARGET_ID,
                verify_owner_exists=_RecordingVerifier(exists=False),
            )
        assert exc_info.value.status_code == 404

    def test_issuer_outage_fails_closed(self) -> None:
        with pytest.raises(OwnerVerificationUnavailable) as exc_info:
            resolve_create_owner_id(
                actor_id=ACTOR_ID,
                actor_is_canonical_superuser=True,
                target_owner_id=TARGET_ID,
                verify_owner_exists=_unavailable_verifier,
            )
        assert exc_info.value.status_code == 503

    def test_no_verifier_configured_fails_closed(self) -> None:
        """The API-key path passes no verifier and must never fall through."""
        with pytest.raises(OwnerVerificationUnavailable):
            resolve_create_owner_id(
                actor_id=ACTOR_ID,
                actor_is_canonical_superuser=True,
                target_owner_id=TARGET_ID,
            )


class TestActorIdIsNeverSubstituted:
    """No refusal path quietly falls back to owning the row to the actor."""

    @pytest.mark.parametrize(
        ("actor_is_canonical_superuser", "verifier"),
        [
            pytest.param(False, _RecordingVerifier(exists=True), id="not-superuser"),
            pytest.param(True, _RecordingVerifier(exists=False), id="unknown-target"),
            pytest.param(True, _unavailable_verifier, id="issuer-unreachable"),
            pytest.param(True, None, id="no-verifier"),
        ],
    )
    def test_every_refusal_raises_instead_of_owning_to_the_actor(
        self,
        actor_is_canonical_superuser: bool,
        verifier: Optional[Any],
    ) -> None:
        with pytest.raises(OwnershipError):
            resolve_create_owner_id(
                actor_id=ACTOR_ID,
                actor_is_canonical_superuser=actor_is_canonical_superuser,
                target_owner_id=TARGET_ID,
                verify_owner_exists=verifier,
            )

    def test_a_resolved_cross_owner_create_persists_the_target(self) -> None:
        """End-to-end over the two collaborating steps the route performs."""
        item_in = CategoryCreate.model_validate(
            {"name": "News", "target_owner_id": str(TARGET_ID)}
        )
        owner_id = resolve_create_owner_id(
            actor_id=ACTOR_ID,
            actor_is_canonical_superuser=is_canonical_superuser(
                _user("superadmin", True)
            ),
            target_owner_id=item_in.target_owner_id,
            verify_owner_exists=_RecordingVerifier(exists=True),
        )
        item = build_category(item_in, owner_id=owner_id)
        assert item.owner_id == TARGET_ID
        assert item.owner_id != ACTOR_ID
