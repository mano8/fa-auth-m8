"""Canonical JWKS ``kid`` derivation — one implementation for the whole product.

Before ``2.1.0`` this repository shipped **two** derivations for the same key:
``examples/docker_compose/shared/scripts/init-keys.sh`` digested the canonical
SPKI **DER** bytes, while ``services.auth._resolve_kid`` digested the **PEM
text**.  The same keypair therefore produced two different ``kid`` values
depending on which path wrote it, and the operator-facing documentation claimed
the two were interchangeable (audit finding ``J2``).

The DER form wins: it is stable across PEM line endings, header spelling and
trailing whitespace, and it is already the operator-facing contract written by
``init-keys.sh``.  This module is that single implementation — the service
fallback (``_resolve_kid``) and the startup binding validator
(``Settings._validate_access_key_id_binding``) both route through it, and
``tests/security/test_kid_derivation.py`` proves it agrees with the shell
script on a freshly generated keypair.

Equivalent shell pipeline (what ``init-keys.sh`` runs)::

    openssl pkey -pubin -in public.pem -pubout -outform DER \
      | openssl dgst -sha256 | awk '{print $NF}' | cut -c1-16
"""

import hashlib

from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_pem_public_key,
)

# Length of the published ``kid``, in hex characters.  64 bits of a SHA-256
# digest: enough to distinguish the keys one issuer serves, short enough to
# stay readable in a JWT header and an ``auth.env`` line.
KID_HEX_LENGTH = 16

__all__ = ["KID_HEX_LENGTH", "derive_kid"]


def derive_kid(public_pem: str) -> str:
    """Return the canonical ``kid`` for a PEM-encoded public key.

    The ``kid`` is the first :data:`KID_HEX_LENGTH` hex characters of the
    SHA-256 digest of the key's canonical SubjectPublicKeyInfo DER encoding.

    Args:
        public_pem: PEM-encoded **public** key (RSA or EC).

    Returns:
        A 16-character lowercase hex key id.

    Raises:
        ValueError: The argument is empty or is not a parsable PEM public key.
            The message never contains key material.
    """
    pem = (public_pem or "").strip()
    if not pem:
        raise ValueError("Cannot derive a kid from an empty public key")
    try:
        key = load_pem_public_key(pem.encode())
    except Exception as exc:  # narrow to a config error; never echo the key
        raise ValueError(
            "Cannot derive a kid: the configured public key is not a parsable "
            "PEM public key"
        ) from exc
    der = key.public_bytes(
        encoding=Encoding.DER,
        format=PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(der).hexdigest()[:KID_HEX_LENGTH]
