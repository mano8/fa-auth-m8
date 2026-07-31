"""Singleton security-policy row backing the portable superuser-set lock.

The last-superuser invariant must be serialized across every transaction that
can add an account to, or remove one from, the active canonical-superuser set.
A ``pg_advisory_xact_lock`` would only work on PostgreSQL; the supported engines
also include MySQL/MariaDB (Â§4.6), so the normative mechanism is a **portable
singleton policy-row lock** (3.5.3 ``REV-LOCK-01``): a ``SELECT ... FOR UPDATE``
on this row serializes all superuser-set mutations on every supported engine.

The table holds exactly one seeded row (``policy_key = 'superuser_set'``). Its
``revision`` counter is bumped by every committed set mutation so the contention
is observable and the lock's participation is provable. This module owns only
the model; the lock protocol and revision bump live in
:mod:`auth_user_service.services.role_admin`.
"""

from datetime import datetime

from sqlalchemy import BigInteger, Column, DateTime, String, text
from sqlmodel import Field, SQLModel

from auth_user_service.core.db_utils import get_table_args, prefixed_tables

#: The single seeded row's primary key — the superuser-set mutation lock.
SUPERUSER_SET_POLICY_KEY = "superuser_set"


class SecurityPolicy(SQLModel, table=True):
    """Issuer-owned singleton lock/coordination row (3.5.3).

    Exactly one row is seeded per ``policy_key``; there is deliberately no
    business data here beyond the monotonic ``revision`` so the row's sole
    purpose — being locked ``FOR UPDATE`` to serialize superuser-set mutations —
    stays unambiguous.
    """

    __tablename__ = prefixed_tables("security_policy")
    __table_args__ = (get_table_args(),)

    policy_key: str = Field(
        sa_column=Column("policy_key", String(64), primary_key=True),
        description="Seeded singleton key (e.g. 'superuser_set').",
    )
    revision: int = Field(
        sa_column=Column(
            "revision",
            BigInteger,
            nullable=False,
            default=0,
            server_default=text("0"),
        ),
        description="Monotonic counter incremented by every committed set mutation.",
    )
    updated_at: datetime = Field(
        sa_column=Column("updated_at", DateTime, nullable=False),
        description="Timestamp of the last committed revision bump (UTC).",
    )
