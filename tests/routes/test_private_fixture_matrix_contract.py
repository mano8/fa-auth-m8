"""Consume the SDK-owned canonical fixture matrix in the issuer (§5.5, FIXTURE-01, Phase 5).

``auth-sdk-m8`` is the single canonical owner of the shared role/flag/
decision/event/introspection fixture matrix. This module drives the issuer's
own request schemas and private-route handlers directly from the canonical
fixture data — rather than re-deriving local expectations — so a contract
change on the SDK side (a new schema version, a changed decision, a checksum
mismatch from a hand-edit) fails this suite too.
``load_authorization_fixture_matrix()`` itself raises
``UnsupportedFixtureMatrixSchemaVersionError``/``FixtureChecksumMismatchError``
on drift or tampering, so importing/calling it here is already part of the CI
gate against contract drift.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from auth_sdk_m8 import ApiKeyAccessMode, has_api_key_capability
from auth_sdk_m8.schemas.api_key import (
    ApiKeyIntrospectionActiveResponse,
    ApiKeyIntrospectionRequest,
    ApiKeyPrincipal,
)
from auth_sdk_m8.schemas.base import RoleType
from auth_sdk_m8.schemas.jti_status import (
    JtiStatusActiveResponse,
    JtiStatusInactiveResponse,
)
from auth_sdk_m8.testing import load_authorization_fixture_matrix
from fastapi import Response

from auth_user_service.routes.private import (
    JtiStatusRequest,
    check_jti_status,
    introspect_api_key,
)
from auth_user_service.services.generation import JtiStatusDecision

_CONSUMER = "prompt-engine-m8"


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture(scope="module")
def matrix() -> dict:
    return load_authorization_fixture_matrix()


class TestJtiStatusRequestAcceptsCanonicalShapes:
    def test_v1_request_shape_is_accepted(self, matrix: dict) -> None:
        req = matrix["jti_status_fixtures"]["v1"]["request"]
        JtiStatusRequest(**req)

    def test_v2_request_shape_is_accepted(self, matrix: dict) -> None:
        req = matrix["jti_status_fixtures"]["v2"]["request"]
        JtiStatusRequest(**req)


class TestCheckJtiStatusProducesCanonicalShapes:
    """The live handler's output must match the fixture's active/inactive shapes."""

    @pytest.mark.anyio
    async def test_stateful_active_decision_matches_fixture_shape(
        self, matrix: dict
    ) -> None:
        v2 = matrix["jti_status_fixtures"]["v2"]
        subject = uuid.UUID(v2["request"]["expected_user_id"])
        generation = v2["active"]["auth_generation"]

        with (
            patch("auth_user_service.routes.private.settings") as mock_cfg,
            patch("auth_user_service.routes.private.GenerationController") as mock_ctrl,
        ):
            mock_cfg.is_stateful = True
            mock_ctrl.decide_jti_status.return_value = JtiStatusDecision(
                active=True, user_id=subject, auth_generation=generation
            )
            result = await check_jti_status(
                body=JtiStatusRequest(**v2["request"]),
                session=MagicMock(),
                redis=None,
            )

        assert isinstance(result, JtiStatusActiveResponse)
        assert result.user_id == v2["request"]["expected_user_id"]
        assert result.auth_generation == generation

    @pytest.mark.anyio
    async def test_stateful_inactive_decision_matches_fixture_shape(
        self, matrix: dict
    ) -> None:
        v2 = matrix["jti_status_fixtures"]["v2"]
        with (
            patch("auth_user_service.routes.private.settings") as mock_cfg,
            patch("auth_user_service.routes.private.GenerationController") as mock_ctrl,
        ):
            mock_cfg.is_stateful = True
            mock_ctrl.decide_jti_status.return_value = JtiStatusDecision(active=False)
            result = await check_jti_status(
                body=JtiStatusRequest(**v2["request"]),
                session=MagicMock(),
                redis=None,
            )
        assert isinstance(result, JtiStatusInactiveResponse)
        assert result.model_dump() == v2["inactive"]

    @pytest.mark.anyio
    async def test_unsupported_schema_version_request_is_generic_inactive(
        self, matrix: dict
    ) -> None:
        bad = matrix["jti_status_fixtures"]["unsupported_schema_version_response"]
        request = JtiStatusRequest(
            jti="j" * 16,
            expected_user_id=uuid.uuid4(),
            schema_version=bad["schema_version"],
        )
        result = await check_jti_status(body=request, session=MagicMock(), redis=None)
        assert isinstance(result, JtiStatusInactiveResponse)


class TestApiKeyIntrospectionRequestAcceptsCanonicalShape:
    def test_request_shape_is_accepted(self, matrix: dict) -> None:
        req = matrix["api_key_introspection_fixtures"]["request"]
        ApiKeyIntrospectionRequest(**req)


def _api_key(audiences=None, expires_at=None) -> SimpleNamespace:
    return SimpleNamespace(
        id=uuid.uuid4(),
        user_id=uuid.uuid4(),
        expires_at=expires_at,
        audiences=audiences if audiences is not None else [],
    )


class TestIntrospectApiKeyProducesCanonicalShapes:
    """The live endpoint's output must match the fixture's principal shapes."""

    async def _call(self, body, *, principal, key):
        redis = MagicMock()
        pipe = MagicMock()
        pipe.execute.return_value = [1, True]
        redis.pipeline.return_value.__enter__.return_value = pipe
        with (
            patch(
                "auth_user_service.routes.private.authenticate_private_consumer",
                return_value=_CONSUMER,
            ),
            patch(
                "auth_user_service.routes.private.ApiKeyService.get_active_key",
                return_value=key,
            ),
            patch(
                "auth_user_service.routes.private.resolve_api_key_owner_principal",
                return_value=principal,
            ),
        ):
            return await introspect_api_key(
                body=body,
                request=MagicMock(),
                response=Response(),
                session=MagicMock(),
                redis=redis,
            )

    @pytest.mark.anyio
    async def test_every_local_remote_pair_resolves_the_same_principal(
        self, matrix: dict
    ) -> None:
        request_fixture = matrix["api_key_introspection_fixtures"]["request"]
        for pair in matrix["local_remote_principal_equivalence"]:
            local = pair["local"]
            principal = ApiKeyPrincipal(
                user_id=local["user_id"],
                role=RoleType(local["role"]),
                is_superuser=local["is_superuser"],
                access_mode=ApiKeyAccessMode(local["access_mode"]),
                auth_generation=local["auth_generation"],
            )
            key = _api_key(
                audiences=[SimpleNamespace(audience_id=_CONSUMER)],
                expires_at=datetime(2030, 1, 1, tzinfo=timezone.utc),
            )
            result = await self._call(
                ApiKeyIntrospectionRequest(**request_fixture),
                principal=principal,
                key=key,
            )
            assert isinstance(result, ApiKeyIntrospectionActiveResponse)
            assert result.principal == principal


class TestAudienceAndCapabilityPolicyMatrixAgainstIssuerLocalAdmission:
    """Issuer-local admission ignores audience entirely (§3.11/§3.12)."""

    def test_issuer_local_allowed_matches_has_api_key_capability(
        self, matrix: dict
    ) -> None:
        for row in matrix["audience_and_capability_policy_matrix"]:
            if row["role"] is None:
                continue
            allowed = has_api_key_capability(
                RoleType(row["role"]),
                RoleType(row["role"]) == RoleType.SUPERADMIN,
                ApiKeyAccessMode(row["access_mode"]),
                RoleType(row["required_role"]),
            )
            assert allowed is row["issuer_local_allowed"]
