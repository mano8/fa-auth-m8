"""Canonical ``kid`` derivation — audit finding ``J2`` (plan step ``W1.1``).

Two derivations used to ship in this product for the same key: the provisioning
script digested the SPKI **DER** bytes, the service digested the **PEM text**.
The service now uses the DER form, and these tests hold the two paths together:

- ``derive_kid`` is the DER digest, not the PEM-text digest (the J2 regression);
- it is stable across PEM formatting (CRLF, trailing whitespace, no trailing
  newline) — the property that made DER the right choice;
- ``init-keys.sh`` — the operator-facing contract that writes ``ACCESS_KEY_ID``
  — computes the *same* value on a freshly generated keypair, executed rather
  than asserted in a comment.
"""

from __future__ import annotations

import hashlib
import shutil
import subprocess
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_pem_public_key,
)

from auth_user_service.core.key_ids import KID_HEX_LENGTH, derive_kid

REPO_ROOT = Path(__file__).resolve().parents[2]
INIT_KEYS = (
    REPO_ROOT / "examples" / "docker_compose" / "shared" / "scripts" / "init-keys.sh"
)

# The kid pipeline init-keys.sh runs, as an argv pair. Kept literal here so a
# change to the script's derivation shows up as a failure in this file too.
_DER_DIGEST_ARGV = (
    ["openssl", "pkey", "-pubin", "-pubout", "-outform", "DER"],
    ["openssl", "dgst", "-sha256"],
)


def _working_bash() -> str | None:
    """Return a bash that can actually execute, or ``None``.

    ``shutil.which("bash")`` on a Windows developer host commonly resolves to
    the WSL launcher stub, which fails to exec. Probe instead of trusting the
    lookup, and fall back to the Git-for-Windows shells. On CI (ubuntu) the
    first candidate answers.
    """
    candidates = [c for c in (shutil.which("bash"),) if c]
    candidates += [
        p
        for p in (
            r"C:\Program Files\Git\bin\bash.exe",
            r"C:\Program Files\Git\usr\bin\bash.exe",
        )
        if Path(p).is_file()
    ]
    for candidate in candidates:
        try:
            probe = subprocess.run(  # nosec B603 - fixed argv, no user input
                [candidate, "-c", "echo m8"],
                check=False,
                text=True,
                capture_output=True,
                timeout=30,
            )
        except OSError:
            continue
        if probe.returncode == 0 and probe.stdout.strip() == "m8":
            return candidate
    return None


def _rsa_public_pem() -> str:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return (
        key.public_key()
        .public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        .decode()
    )


def _ec_public_pem() -> str:
    key = ec.generate_private_key(ec.SECP256R1())
    return (
        key.public_key()
        .public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        .decode()
    )


# ── shape ─────────────────────────────────────────────────────────────────────


@pytest.mark.security
def test_derive_kid_is_16_lowercase_hex_chars() -> None:
    kid = derive_kid(_rsa_public_pem())
    assert len(kid) == KID_HEX_LENGTH == 16
    assert kid == kid.lower()
    int(kid, 16)  # parses as hex


@pytest.mark.security
def test_derive_kid_supports_ec_keys() -> None:
    """ES256 stacks derive a kid the same way — the script handles both."""
    kid = derive_kid(_ec_public_pem())
    assert len(kid) == KID_HEX_LENGTH


# ── J2: DER, not PEM text ─────────────────────────────────────────────────────


@pytest.mark.security
def test_derive_kid_digests_der_not_pem_text() -> None:
    """The J2 regression guard: the two derivations must not be confused again."""
    pem = _rsa_public_pem()
    der = load_pem_public_key(pem.encode()).public_bytes(
        Encoding.DER, PublicFormat.SubjectPublicKeyInfo
    )
    assert derive_kid(pem) == hashlib.sha256(der).hexdigest()[:16]
    assert derive_kid(pem) != hashlib.sha256(pem.strip().encode()).hexdigest()[:16]


@pytest.mark.security
def test_derive_kid_is_stable_across_pem_formatting() -> None:
    """Why DER wins: line endings and stray whitespace must not move the kid."""
    pem = _rsa_public_pem()
    expected = derive_kid(pem)

    assert derive_kid(pem.replace("\n", "\r\n")) == expected
    assert derive_kid(pem.rstrip("\n")) == expected
    assert derive_kid(f"\n\n  {pem}  \n\n") == expected


@pytest.mark.security
def test_derive_kid_is_deterministic() -> None:
    pem = _rsa_public_pem()
    assert derive_kid(pem) == derive_kid(pem)


@pytest.mark.security
def test_derive_kid_separates_distinct_keys() -> None:
    assert derive_kid(_rsa_public_pem()) != derive_kid(_rsa_public_pem())


# ── invalid input fails closed, without echoing key material ─────────────────


@pytest.mark.security
@pytest.mark.parametrize("bad", ["", "   ", "not-a-pem", "-----BEGIN PUBLIC KEY-----"])
def test_derive_kid_rejects_unparsable_input(bad: str) -> None:
    with pytest.raises(ValueError) as exc:
        derive_kid(bad)
    if bad.strip():
        assert bad.strip() not in str(exc.value)


@pytest.mark.security
def test_derive_kid_error_does_not_leak_key_material() -> None:
    """A private key handed in by mistake must not be echoed into the message."""
    private_pem = (
        rsa.generate_private_key(public_exponent=65537, key_size=2048)
        .private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
        .decode()
    )
    with pytest.raises(ValueError) as exc:
        derive_kid(private_pem)
    body = "".join(private_pem.splitlines()[1:-1])
    assert body[:32] not in str(exc.value)


# ── the service and the provisioning script agree ────────────────────────────


@pytest.mark.security
def test_openssl_der_pipeline_matches_derive_kid(tmp_path: Path) -> None:
    """The script's kid pipeline, run directly against a generated key.

    Needs only ``openssl``, so it holds the derivations together on hosts
    without a usable bash;
    :func:`test_init_keys_script_and_service_derive_the_same_kid` is the
    end-to-end proof.
    """
    if shutil.which("openssl") is None:
        pytest.skip("openssl is required for the DER digest pipeline")

    pem_path = tmp_path / "public.pem"
    pem_path.write_text(_rsa_public_pem(), encoding="utf-8")

    der = subprocess.run(  # nosec B603 - fixed argv, generated key file
        [*_DER_DIGEST_ARGV[0], "-in", str(pem_path)],
        check=True,
        capture_output=True,
    ).stdout
    digest = subprocess.run(  # nosec B603 - fixed argv
        list(_DER_DIGEST_ARGV[1]),
        input=der,
        check=True,
        capture_output=True,
    ).stdout.decode()

    script_kid = digest.split()[-1][:16]
    assert script_kid == derive_kid(pem_path.read_text(encoding="utf-8"))


@pytest.mark.security
@pytest.mark.parametrize("algorithm", ["RS256", "ES256"])
def test_init_keys_script_and_service_derive_the_same_kid(
    tmp_path: Path, algorithm: str
) -> None:
    """``init-keys.sh`` writes ``ACCESS_KEY_ID``; the service must agree with it.

    Runs the real script against a throwaway stack directory and compares the
    ``ACCESS_KEY_ID`` it wrote with :func:`derive_kid` of the public key it
    generated. This is the acceptance test for ``W1.1``: one derivation in the
    product, proven equal rather than asserted.
    """
    bash = _working_bash()
    if bash is None or shutil.which("openssl") is None:
        pytest.skip("bash and openssl are required to execute init-keys.sh")

    (tmp_path / "auth.env").write_text(
        f"ACCESS_TOKEN_ALGORITHM={algorithm}\nACCESS_KEY_ID=changethis_hex_kid\n",
        encoding="utf-8",
    )

    result = subprocess.run(  # nosec B603 B607 - fixed repo script, no user input
        [bash, str(INIT_KEYS)],
        cwd=str(tmp_path),
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    assert result.returncode == 0, result.stdout

    written = [
        line.split("=", 1)[1].strip()
        for line in (tmp_path / "auth.env").read_text(encoding="utf-8").splitlines()
        if line.startswith("ACCESS_KEY_ID=")
    ]
    assert written, f"init-keys.sh did not write ACCESS_KEY_ID:\n{result.stdout}"

    public_pem = (tmp_path / "keys" / "public.pem").read_text(encoding="utf-8")
    assert written[0] == derive_kid(public_pem), (
        "init-keys.sh and derive_kid disagree on the kid for the same key — "
        "the J2 split has reopened"
    )
