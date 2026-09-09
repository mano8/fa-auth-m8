"""Dual-key JWKS overlap window — audit finding ``J3`` (plan step ``W1.3``).

Before ``2.1.0`` the endpoint published exactly one JWK, so every keypair
rotation was a hard cutover: access tokens signed under the previous key were
rejected the moment consumers reloaded JWKS, and the only way to shrink the gap
was to restart every consumer. ``SECURITY.md`` said as much in writing.

With ``ACCESS_PUBLIC_KEY_OLD_FILE`` set the endpoint publishes both keys, the
old one for verification only. These tests cover the acceptance criteria for
``W1.3``: two JWKs with distinct kids, signing under the current kid only, an
old-key token still verifying, and a clean return to one key when the pair is
unset — plus the structural misconfigurations that must never boot.
"""

from __future__ import annotations

import shutil
import subprocess
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)
from pydantic import ValidationError

from auth_user_service.core.key_ids import derive_kid
from auth_user_service.routes.jwks import build_key_set

from tests.security.test_access_key_id_binding import _make, _write_rsa_keypair
from tests.security.test_kid_derivation import INIT_KEYS, _working_bash


def _read_env(path: Path) -> dict[str, str]:
    return dict(
        line.split("=", 1)  # type: ignore[misc]
        for line in path.read_text(encoding="utf-8").splitlines()
        if "=" in line and not line.startswith("#")
    )


def _rsa_keypair() -> tuple[str, str]:
    """Return (private PEM, public PEM) for a fresh 2048-bit RSA key."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = key.private_bytes(
        Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
    ).decode()
    public_pem = (
        key.public_key()
        .public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        .decode()
    )
    return private_pem, public_pem


@pytest.fixture
def rotation_pair():
    """A current and a previous RSA keypair, with their canonical kids."""
    current_private, current_public = _rsa_keypair()
    old_private, old_public = _rsa_keypair()
    return {
        "current_private": current_private,
        "current_public": current_public,
        "current_kid": derive_kid(current_public),
        "old_private": old_private,
        "old_public": old_public,
        "old_kid": derive_kid(old_public),
    }


def _key_set(current_public: str, old_public: str | None, old_kid: str | None = None):
    with (
        patch("auth_user_service.routes.jwks.settings") as mock_settings,
        patch(
            "auth_user_service.routes.jwks._resolve_kid",
            return_value=derive_kid(current_public),
        ),
    ):
        mock_settings.ACCESS_TOKEN_ALGORITHM = "RS256"
        mock_settings.ACCESS_PUBLIC_KEY = current_public
        mock_settings.ACCESS_PUBLIC_KEY_OLD = old_public
        mock_settings.ACCESS_KEY_ID_OLD = old_kid
        return build_key_set()


# ── the published key set ────────────────────────────────────────────────────


@pytest.mark.security
def test_overlap_window_publishes_two_keys_with_distinct_kids(rotation_pair) -> None:
    result = _key_set(rotation_pair["current_public"], rotation_pair["old_public"])

    kids = [k["kid"] for k in result["keys"]]
    assert len(result["keys"]) == 2
    assert kids == [rotation_pair["current_kid"], rotation_pair["old_kid"]]
    assert len(set(kids)) == 2


@pytest.mark.security
def test_current_key_is_published_first(rotation_pair) -> None:
    """A consumer that naively takes keys[0] must get the signing key."""
    result = _key_set(rotation_pair["current_public"], rotation_pair["old_public"])
    assert result["keys"][0]["kid"] == rotation_pair["current_kid"]


@pytest.mark.security
def test_closing_the_window_returns_a_single_key(rotation_pair) -> None:
    result = _key_set(rotation_pair["current_public"], None)
    assert len(result["keys"]) == 1
    assert result["keys"][0]["kid"] == rotation_pair["current_kid"]


@pytest.mark.security
def test_old_kid_is_derived_when_not_configured(rotation_pair) -> None:
    """Leaving ACCESS_KEY_ID_OLD unset is safe: the kid comes from the key."""
    result = _key_set(
        rotation_pair["current_public"], rotation_pair["old_public"], old_kid=None
    )
    assert result["keys"][1]["kid"] == rotation_pair["old_kid"]


@pytest.mark.security
def test_every_published_kid_is_its_own_jwk_fingerprint(rotation_pair) -> None:
    """The invariant the live regression test (W3.5) asserts against a stack."""
    result = _key_set(rotation_pair["current_public"], rotation_pair["old_public"])
    for jwk, pem in zip(
        result["keys"], [rotation_pair["current_public"], rotation_pair["old_public"]]
    ):
        assert jwk["kid"] == derive_kid(pem)
        assert jwk["use"] == "sig"
        assert jwk["alg"] == "RS256"


@pytest.mark.security
def test_no_private_material_is_published(rotation_pair) -> None:
    result = _key_set(rotation_pair["current_public"], rotation_pair["old_public"])
    private_members = {"d", "p", "q", "dp", "dq", "qi", "oth"}
    for jwk in result["keys"]:
        assert not private_members & set(jwk)
        assert {"kty", "n", "e", "use", "alg", "kid"} <= set(jwk)


# ── signing stays on the current key ─────────────────────────────────────────


@pytest.mark.security
def test_tokens_are_signed_under_the_current_kid_only(rotation_pair) -> None:
    """The old key is verification-only — never a signing input."""
    from auth_sdk_m8.schemas.auth import TokenAccessData, TokenSecret
    from auth_user_service.core.security import SecurityHelper

    data = TokenAccessData(
        sub="user-123",
        full_name="Test User",
        email="test@example.com",
        avatar=None,
        is_active=True,
        email_verified=True,
        is_superuser=False,
        role="user",
    )
    token, _ = SecurityHelper.create_access_token(
        data=data,
        expires_delta=timedelta(minutes=15),
        secrets=TokenSecret(
            secret_key=rotation_pair["current_private"], algorithm="RS256"
        ),
        kid=rotation_pair["current_kid"],
    )

    header = jwt.get_unverified_header(token)
    assert header["kid"] == rotation_pair["current_kid"]
    assert header["kid"] != rotation_pair["old_kid"]


@pytest.mark.security
def test_a_token_signed_under_the_old_key_still_verifies(rotation_pair) -> None:
    """The point of the window: pre-rotation tokens keep validating.

    Selects the JWK by the token's kid exactly as ``JwksKeyResolver`` does, then
    verifies the signature against it — the consumer path, without a restart.
    """
    from jwt.algorithms import RSAAlgorithm

    token = jwt.encode(
        {"sub": "user-123"},
        rotation_pair["old_private"],
        algorithm="RS256",
        headers={"kid": rotation_pair["old_kid"]},
    )

    published = _key_set(rotation_pair["current_public"], rotation_pair["old_public"])
    by_kid = {k["kid"]: k for k in published["keys"]}
    kid = jwt.get_unverified_header(token)["kid"]
    assert kid in by_kid, "the old kid must still be resolvable from JWKS"

    import json

    key = RSAAlgorithm.from_jwk(json.dumps(by_kid[kid]))
    assert jwt.decode(token, key, algorithms=["RS256"])["sub"] == "user-123"


@pytest.mark.security
def test_an_old_key_token_stops_verifying_once_the_window_closes(
    rotation_pair,
) -> None:
    """Retiring the _OLD pair is what actually invalidates the old tokens."""
    token = jwt.encode(
        {"sub": "user-123"},
        rotation_pair["old_private"],
        algorithm="RS256",
        headers={"kid": rotation_pair["old_kid"]},
    )

    published = _key_set(rotation_pair["current_public"], None)
    kids = {k["kid"] for k in published["keys"]}
    assert jwt.get_unverified_header(token)["kid"] not in kids


# ── configurations that must not boot ────────────────────────────────────────


@pytest.mark.security
def test_old_key_id_without_the_old_key_file_fails(tmp_path: Path) -> None:
    _, public_path, _ = _write_rsa_keypair(tmp_path)
    with pytest.raises(ValidationError) as exc:
        _make(
            ACCESS_TOKEN_ALGORITHM="RS256",
            ACCESS_PUBLIC_KEY_FILE=str(public_path),
            ACCESS_KEY_ID_OLD="deadbeefdeadbeef",
        )
    assert "ACCESS_PUBLIC_KEY_OLD_FILE" in str(exc.value)


@pytest.mark.security
def test_unbound_old_key_id_fails(tmp_path: Path) -> None:
    _, public_path, _ = _write_rsa_keypair(tmp_path)
    old_dir = tmp_path / "old"
    old_dir.mkdir()
    _, old_public_path, old_pem = _write_rsa_keypair(old_dir)

    with pytest.raises(ValidationError) as exc:
        _make(
            ACCESS_TOKEN_ALGORITHM="RS256",
            ACCESS_PUBLIC_KEY_FILE=str(public_path),
            ACCESS_PUBLIC_KEY_OLD_FILE=str(old_public_path),
            ACCESS_KEY_ID_OLD="deadbeefdeadbeef",
        )
    assert derive_kid(old_pem) in str(exc.value)


@pytest.mark.security
def test_the_same_key_in_both_slots_fails(tmp_path: Path) -> None:
    """Two JWKs under one kid is the defect this release closes."""
    _, public_path, _ = _write_rsa_keypair(tmp_path)
    with pytest.raises(ValidationError) as exc:
        _make(
            ACCESS_TOKEN_ALGORITHM="RS256",
            ACCESS_PUBLIC_KEY_FILE=str(public_path),
            ACCESS_PUBLIC_KEY_OLD_FILE=str(public_path),
        )
    assert "one kid" in str(exc.value)


@pytest.mark.security
def test_the_same_key_in_both_slots_is_not_excused_by_break_glass(
    tmp_path: Path,
) -> None:
    _, public_path, _ = _write_rsa_keypair(tmp_path)
    with pytest.raises(ValidationError):
        _make(
            ACCESS_TOKEN_ALGORITHM="RS256",
            ACCESS_PUBLIC_KEY_FILE=str(public_path),
            ACCESS_PUBLIC_KEY_OLD_FILE=str(public_path),
            ACCESS_KEY_ID_ALLOW_UNBOUND=True,
        )


@pytest.mark.security
def test_an_old_key_of_the_wrong_type_fails(tmp_path: Path) -> None:
    """An EC key on an RS256 stack would serialize into a malformed JWK."""
    _, public_path, _ = _write_rsa_keypair(tmp_path)
    ec_public = tmp_path / "ec_public.pem"
    ec_public.write_text(
        ec.generate_private_key(ec.SECP256R1())
        .public_key()
        .public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        .decode(),
        encoding="utf-8",
    )

    with pytest.raises(ValidationError) as exc:
        _make(
            ACCESS_TOKEN_ALGORITHM="RS256",
            ACCESS_PUBLIC_KEY_FILE=str(public_path),
            ACCESS_PUBLIC_KEY_OLD_FILE=str(ec_public),
        )
    assert "cannot span key types" in str(exc.value)


@pytest.mark.security
def test_a_missing_old_key_file_fails(tmp_path: Path) -> None:
    _, public_path, _ = _write_rsa_keypair(tmp_path)
    with pytest.raises(ValidationError) as exc:
        _make(
            ACCESS_TOKEN_ALGORITHM="RS256",
            ACCESS_PUBLIC_KEY_FILE=str(public_path),
            ACCESS_PUBLIC_KEY_OLD_FILE=str(tmp_path / "absent.pem"),
        )
    assert "ACCESS_PUBLIC_KEY_OLD_FILE not found" in str(exc.value)


@pytest.mark.security
def test_hs256_rejects_a_rotation_overlap_pair(tmp_path: Path) -> None:
    """HS256 publishes no key set, so the pair can only be a mistake."""
    _, public_path, _ = _write_rsa_keypair(tmp_path)
    with pytest.raises(ValidationError) as exc:
        _make(ACCESS_PUBLIC_KEY_OLD_FILE=str(public_path))
    assert "publishes no key set" in str(exc.value)


# ── the provisioning script opens the window ─────────────────────────────────


@pytest.mark.security
def test_init_keys_rotate_opens_a_bound_overlap_window(tmp_path: Path) -> None:
    """``init-keys.sh --rotate`` must produce a *bound* pair, not just new keys.

    The precondition for W3.1 and for the SECURITY.md rotation runbook: one
    command leaves the stack with a new keypair, its kid, the retained previous
    public key, and that key's kid — all written together so none can drift.
    """
    bash = _working_bash()
    if bash is None or shutil.which("openssl") is None:
        pytest.skip("bash and openssl are required to execute init-keys.sh")

    (tmp_path / "auth.env").write_text(
        "ACCESS_TOKEN_ALGORITHM=RS256\n"
        "ACCESS_PRIVATE_KEY_FILE=/opt/keys/private.pem\n"
        "ACCESS_PUBLIC_KEY_FILE=/opt/keys/public.pem\n"
        "ACCESS_KEY_ID=changethis_hex_kid\n",
        encoding="utf-8",
    )

    def run(*args: str) -> None:
        result = subprocess.run(  # nosec B603 - fixed repo script, no user input
            [bash, str(INIT_KEYS), *args],
            cwd=str(tmp_path),
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        assert result.returncode == 0, result.stdout

    run()
    first_public = (tmp_path / "keys" / "public.pem").read_text(encoding="utf-8")
    assert _read_env(tmp_path / "auth.env")["ACCESS_KEY_ID"] == derive_kid(first_public)

    run("--rotate")

    env = _read_env(tmp_path / "auth.env")
    retained = tmp_path / "keys" / "public_old.pem"
    new_public = (tmp_path / "keys" / "public.pem").read_text(encoding="utf-8")

    assert retained.read_text(encoding="utf-8") == first_public
    assert new_public != first_public
    assert env["ACCESS_KEY_ID"] == derive_kid(new_public)
    assert env["ACCESS_KEY_ID_OLD"] == derive_kid(first_public)
    assert env["ACCESS_KEY_ID"] != env["ACCESS_KEY_ID_OLD"]
    # Path follows the stack's own mount, not a hardcoded /opt/keys.
    assert env["ACCESS_PUBLIC_KEY_OLD_FILE"] == "/opt/keys/public_old.pem"
    # The retired private key must not be kept around.
    assert not (tmp_path / "keys" / "private_old.pem").exists()


@pytest.mark.security
def test_a_bound_rotation_pair_boots(tmp_path: Path) -> None:
    _, public_path, public_pem = _write_rsa_keypair(tmp_path)
    old_dir = tmp_path / "old"
    old_dir.mkdir()
    _, old_public_path, old_pem = _write_rsa_keypair(old_dir)

    settings = _make(
        ACCESS_TOKEN_ALGORITHM="RS256",
        ACCESS_PUBLIC_KEY_FILE=str(public_path),
        ACCESS_KEY_ID=derive_kid(public_pem),
        ACCESS_PUBLIC_KEY_OLD_FILE=str(old_public_path),
        ACCESS_KEY_ID_OLD=derive_kid(old_pem),
    )

    assert settings.ACCESS_PUBLIC_KEY_OLD == old_pem.strip()
    assert settings.access_key_id_binding_warning is None
