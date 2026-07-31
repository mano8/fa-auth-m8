"""Property-based (Hypothesis) coverage of the issuer authorization predicates.

Complements the fixed-matrix suites (``test_role_admin``, ``test_generation``,
``users_test``) with generated coverage of the pure predicates fa-auth composes
on top of the SDK invariant: the centralized active-canonical-superuser
predicate, the promotion predicate, the server-side flag derivation, the
generation increment/staleness primitives, malformed-role fail-closed behaviour,
and serialization round trips (§6 fa-auth verification plan, 3.5/3.5.1/3.5.3).

These are deliberately DB-free: Hypothesis re-runs the body many times per
example and does not reset function-scoped fixtures between examples, so the
predicates are proven over the whole input space, not only the hand-picked rows.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from auth_sdk_m8.authorization import (
    has_minimum_role,
    has_superuser_privileges,
    privilege_claims_are_consistent,
)
from auth_sdk_m8.schemas.base import RoleType

from auth_user_service.db_models.users import UserPublic
from auth_user_service.services.generation import (
    GENERATION_MAX,
    GENERATION_START,
    GenerationOverflowError,
    is_session_generation_stale,
    next_generation,
)
from auth_user_service.services.role_admin import (
    _is_promotion,
    _would_be_active_canonical_superuser,
    is_active_canonical_superuser,
)
from auth_user_service.services.users import _derive_is_superuser

_roles = st.sampled_from(list(RoleType))
_flags = st.booleans()

#: A role-shaped object that is not a real ``RoleType`` member, for the
#: malformed-input fail-closed branch (mirrors the SDK property suite).
_malformed_roles = st.builds(
    lambda value: type("_FakeRole", (), {"value": value})(),
    st.text(min_size=1, max_size=20).filter(
        lambda s: s not in {r.value for r in RoleType}
    ),
)


class _StubUser:
    """Minimal duck-typed user for the centralized predicate.

    ``is_active_canonical_superuser`` reads only ``role``/``is_superuser``/
    ``is_active``; a stub lets Hypothesis explore every (possibly inconsistent)
    pair without tripping the ``User`` model's construction-time invariant.
    """

    def __init__(self, role: Any, is_superuser: bool, is_active: bool) -> None:
        self.role = role
        self.is_superuser = is_superuser
        self.is_active = is_active


class TestDeriveIsSuperuser:
    @given(role=_roles)
    def test_true_only_for_superadmin(self, role: RoleType) -> None:
        assert _derive_is_superuser(role) is (role == RoleType.SUPERADMIN)

    @given(role=_roles)
    def test_derived_pair_is_always_consistent(self, role: RoleType) -> None:
        # The single derivation point must always yield a canonical pair.
        assert privilege_claims_are_consistent(role, _derive_is_superuser(role))


class TestActiveCanonicalSuperuserPredicate:
    @given(role=_roles, flag=_flags, active=_flags)
    def test_matches_dual_evidence_and_active(
        self, role: RoleType, flag: bool, active: bool
    ) -> None:
        user = _StubUser(role, flag, active)
        expected = has_superuser_privileges(role, flag) and active
        assert is_active_canonical_superuser(user) is expected

    @given(flag=_flags, active=_flags)
    def test_inconsistent_pair_is_never_counted(self, flag: bool, active: bool) -> None:
        # A non-SUPERADMIN role with is_superuser=True is inconsistent and must
        # never be treated as a superuser, whatever the active flag.
        user = _StubUser(RoleType.ADMIN, True, active)
        assert is_active_canonical_superuser(user) is False

    @given(role=_malformed_roles, active=_flags)
    def test_malformed_role_fails_closed(self, role: Any, active: bool) -> None:
        assert is_active_canonical_superuser(_StubUser(role, True, active)) is False

    @given(active=_flags)
    def test_would_be_derives_the_flag(self, active: bool) -> None:
        # The intended-state predicate derives the flag, so only SUPERADMIN can
        # ever be a would-be active canonical superuser.
        for role in RoleType:
            expected = role == RoleType.SUPERADMIN and active
            assert _would_be_active_canonical_superuser(role, active) is expected


class TestPromotionPredicate:
    @given(role=_roles)
    def test_same_role_is_never_a_promotion(self, role: RoleType) -> None:
        assert _is_promotion(role, role) is False

    @given(previous=_roles, intended=_roles)
    def test_matches_strict_ordered_comparison(
        self, previous: RoleType, intended: RoleType
    ) -> None:
        ordered = RoleType.get_ordered_roles()
        expected = intended != previous and (
            ordered.index(intended.value) < ordered.index(previous.value)
        )
        assert _is_promotion(previous, intended) is expected

    @given(previous=_roles, intended=_roles)
    def test_antisymmetric(self, previous: RoleType, intended: RoleType) -> None:
        # Two distinct roles cannot each promote the other.
        assert not (
            _is_promotion(previous, intended) and _is_promotion(intended, previous)
        )

    @given(previous=_roles, intended=_roles)
    def test_agrees_with_has_minimum_role(
        self, previous: RoleType, intended: RoleType
    ) -> None:
        if intended != previous:
            assert _is_promotion(previous, intended) is has_minimum_role(
                intended, previous
            )


class TestGenerationPrimitives:
    @given(
        current=st.integers(min_value=GENERATION_START, max_value=GENERATION_MAX - 1)
    )
    def test_increment_is_strictly_monotonic(self, current: int) -> None:
        assert next_generation(current) == current + 1
        assert next_generation(current) > current

    @given(current=st.integers(min_value=GENERATION_MAX, max_value=2**70))
    def test_fails_closed_at_or_above_ceiling(self, current: int) -> None:
        with pytest.raises(GenerationOverflowError):
            next_generation(current)

    @given(owner=st.integers(min_value=GENERATION_START, max_value=2**62))
    def test_legacy_none_stamp_is_always_stale(self, owner: int) -> None:
        assert is_session_generation_stale(None, owner) is True

    @given(
        stamp=st.integers(min_value=0, max_value=2**62),
        owner=st.integers(min_value=0, max_value=2**62),
    )
    def test_stale_iff_not_equal(self, stamp: int, owner: int) -> None:
        assert is_session_generation_stale(stamp, owner) is (stamp != owner)


class TestSerializationRoundTrips:
    @given(role=_roles, active=_flags)
    def test_public_user_round_trip_preserves_authorization_fields(
        self, role: RoleType, active: bool
    ) -> None:
        flag = _derive_is_superuser(role)
        original = UserPublic(
            id=uuid.uuid4(),
            email="round.trip@example.com",
            role=role,
            is_superuser=flag,
            is_active=active,
        )
        restored = UserPublic.model_validate(original.model_dump())
        assert restored.role == role
        assert restored.is_superuser is flag
        assert restored.is_active is active
        # The round-tripped pair remains canonical.
        assert privilege_claims_are_consistent(restored.role, restored.is_superuser)
