"""
Session Controller

Handles creation and management of secure user sessions using
Redis for revocation and SQLModel for persistence.
"""

import logging
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional, Union

from redis import Redis
from collections.abc import Sequence
from sqlmodel import Session, col, select, delete
from auth_sdk_m8.schemas.user_events import SessionRevokedEvent
from auth_user_service.core.config import settings
from auth_user_service.db_models.users import User
from auth_user_service.db_models.sessions import ClientSessionCreate, ClientSession
from auth_user_service.core.client import RedisRefreshStore, RedisSessionManager
from auth_user_service.core.deps import CurrentUser, get_redis_client
from auth_user_service.events import EVENT_SESSION_REVOKED, emit

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class RevocationTarget:
    """A captured access-session identifier plus its natural expiry.

    Captured *before* the DB rows are deleted so the post-commit accelerator
    (Redis blacklist + refresh-store revoke) can still write a TTL-bounded
    blacklist entry after the authoritative delete has committed.
    """

    jti: str
    expires_at: datetime


class SessionController:
    """Manage user login sessions combining DB and Redis logic."""

    @staticmethod
    def create_client_session(
        *, session: Session, current_user: User, session_data: ClientSessionCreate
    ) -> ClientSession:
        """
        Persist a new session for the current user, storing both
        internal JWT tokens and external Google tokens, and
        register the internal JTI in Redis for revocation.

        Args:
            session (Session): SQLModel DB session.
            current_user (User): Authenticated user.
            session_data (ClientSessionCreate): Session details.

        Returns:
            ClientSession: The newly created session record.
        """
        statement = select(ClientSession).where(
            ClientSession.user_id == current_user.id
        )
        db_session = session.exec(statement).first()
        # Stamp the owner's current authorization generation at issuance so a
        # session minted before a later role/is_active change is detectably stale
        # (3.5.1). Reusing an existing row re-stamps to the current generation for
        # the same reason.
        current_generation = current_user.auth_generation
        if db_session is not None:
            # Session already exists, update it
            db_session.provider = current_user.provider
            db_session.jwt_jti = session_data.jwt_jti
            db_session.refresh_token_hash = session_data.refresh_token_hash
            db_session.jwt_expires_at = session_data.jwt_expires_at
            db_session.refresh_expires_at = session_data.refresh_expires_at
            db_session.external_access_token = session_data.external_access_token
            db_session.external_refresh_token = session_data.external_refresh_token
            db_session.external_token_expires_at = (
                session_data.external_token_expires_at
            )
            db_session.auth_generation = current_generation
        else:
            db_session = ClientSession(
                user_id=current_user.id,
                provider=current_user.provider,
                jwt_jti=session_data.jwt_jti,
                refresh_token_hash=session_data.refresh_token_hash,
                jwt_expires_at=session_data.jwt_expires_at,
                refresh_expires_at=session_data.refresh_expires_at,
                external_access_token=session_data.external_access_token,
                external_refresh_token=session_data.external_refresh_token,
                external_token_expires_at=session_data.external_token_expires_at,
                revoked=False,
                auth_generation=current_generation,
            )
        session.add(db_session)
        session.commit()
        session.refresh(db_session)

        return db_session

    @staticmethod
    def revoke_session_jti(
        jti: str,
        expires_at: datetime,
        redis: Optional[Redis] = None,
        *,
        session: Session,
        user_id: Optional[str] = None,
    ) -> None:
        """Revoke a single access JTI — database-authoritative (3.5.4).

        The authoritative ``ClientSession`` row is deleted **first**, in this
        same operation, and committed; only then are the accelerators applied.
        The Redis blacklist entry and the ``session-revoked`` event merely evict
        consumer caches ahead of expiry, so a Redis outage can never lose the
        revocation: a fresh v2 JTI-status decision denies from database state
        alone (`REV-PATH-01`). ``session`` is therefore mandatory — a Redis-only
        call is not a revocation.

        Args:
            jti (str): JWT token identifier.
            expires_at (datetime): When the token would naturally expire.
            redis: Live Redis client, or None when Redis is unavailable.
            session: SQLModel DB session owning the authoritative delete.
            user_id: Owner of the session. When supplied, a best-effort
                ``session-revoked`` event is pushed so consumers can evict the
                cached validation of this JTI ahead of expiry.
        """
        # 1. Authoritative revocation: remove the DB session row and commit.
        SessionController._delete_session_rows_by_jti(session, jti)
        session.commit()

        # 2. Accelerator: TTL-bounded Redis blacklist entry for the access JTI.
        now = datetime.now(timezone.utc)

        if expires_at.tzinfo is None:
            # assume UTC if naïve
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        raw_ttl = int((expires_at - now).total_seconds())
        if raw_ttl >= 0 and redis is not None:
            safe_ttl = max(raw_ttl, 0)
            RedisSessionManager(redis).blacklist_jti(jti, safe_ttl)
        else:
            logger.warning(
                "Not blacklisting JTI %s because TTL was %d seconds", jti, raw_ttl
            )
        # 3. Accelerator: best-effort cache-eviction event.
        if user_id is not None:
            emit(
                EVENT_SESSION_REVOKED,
                SessionRevokedEvent(user_id=user_id, jti=jti).model_dump(),
            )

    @staticmethod
    def is_session_revoked(jti: str) -> bool:
        """
        Check if a JWT identifier is blacklisted.

        When Redis is unavailable, follows the configured
        ACCESS_REVOCATION_FAILURE_MODE: fail_closed returns True (treats token
        as revoked — revocation takes priority over availability) and fail_open
        returns False (allows the request through). This is an explicit security
        decision matching the pattern in core/deps.py.

        Args:
            jti (str): JWT token identifier.

        Returns:
            bool: True if token is blacklisted or Redis is unavailable and
                  fail_closed mode is active.
        """
        redis = get_redis_client()
        if redis is None:
            mode = settings.effective_failure_mode("access_revocation")
            return mode == "fail_closed"
        return RedisSessionManager(redis).is_blacklisted(jti)

    @staticmethod
    def _delete_session_rows_by_jti(session: Session, jti: str) -> int:
        """Delete the authoritative session row(s) for *jti* — no commit (3.5.4).

        Transaction-neutral primitive shared by every single-JTI revocation
        path, so none of them can degrade into a Redis-only write. Returns the
        number of rows removed.
        """
        stmt = delete(ClientSession).where(col(ClientSession.jwt_jti) == jti)
        result = session.exec(stmt)  # type: ignore[call-overload]
        return int(result.rowcount or 0)

    @staticmethod
    def delete_session_by_jti(
        session: Session, jti: str, *, user_id: Optional[str] = None
    ) -> None:
        """Delete the DB session record for the given JTI.

        Args:
            session: SQLModel DB session.
            jti: JWT identifier of the session to remove.
            user_id: Owner of the session. When supplied, a best-effort
                ``session-revoked`` event is pushed for cache eviction.
        """
        SessionController._delete_session_rows_by_jti(session, jti)
        session.commit()
        if user_id is not None:
            emit(
                EVENT_SESSION_REVOKED,
                SessionRevokedEvent(user_id=user_id, jti=jti).model_dump(),
            )

    @staticmethod
    def purge_expired_sessions(
        session: Session,
        current_user: CurrentUser,
    ) -> int:
        """
        Remove expired sessions from the database.

        Sessions are considered expired if their
        `refresh_expires_at` is before the current time.

        Args:
            session: SQLModel DB session.

        Returns:
            Number of sessions deleted.
        """
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        stmt = delete(ClientSession).where(
            col(ClientSession.user_id) == current_user.id,
            col(ClientSession.refresh_expires_at) < now,
        )
        result = session.exec(stmt)
        deleted = result.rowcount or 0
        if deleted:
            session.commit()
        return deleted

    @staticmethod
    def get_user_active_sessions(
        session: Session, user_id: Union[uuid.UUID, str]
    ) -> Sequence[ClientSession]:
        """
        Retrieve all non-revoked, non-expired sessions for a user.

        Args:
            session: SQLModel DB session.
            user_id: The user's UUID.

        Returns:
            List of active ClientSession objects.
        """
        now = datetime.now(timezone.utc)
        stmt = select(ClientSession).where(
            ClientSession.user_id == user_id,
            ClientSession.revoked == False,  # noqa: E712
            ClientSession.refresh_expires_at > now,
        )
        return session.exec(stmt).all()

    @staticmethod
    def capture_and_delete_user_sessions(
        session: Session, user_id: Union[uuid.UUID, str]
    ) -> tuple[list[RevocationTarget], int]:
        """Delete every DB session row for *user_id* — transaction-neutral (3.5).

        Captures the currently-active access JTIs (with their expiries) for the
        post-commit blacklist accelerator, then deletes **all** of the user's
        ``ClientSession`` rows so the authoritative revocation is persisted in the
        caller's transaction. It does **not** commit, touch Redis, or emit an
        event — the route-owned transaction owns the commit and calls
        :meth:`apply_post_commit_revocation` afterwards. Returns the captured
        targets and the number of rows deleted.
        """
        active = SessionController.get_user_active_sessions(session, user_id)
        targets = [
            RevocationTarget(jti=s.jwt_jti, expires_at=s.jwt_expires_at) for s in active
        ]
        stmt = delete(ClientSession).where(col(ClientSession.user_id) == user_id)
        result = session.exec(stmt)
        return targets, result.rowcount or 0

    @staticmethod
    def apply_post_commit_revocation(
        targets: Sequence[RevocationTarget],
        user_id: Union[uuid.UUID, str],
        redis: Optional[Redis],
        *,
        user_wide: bool = True,
    ) -> None:
        """Best-effort Redis blacklist + revoked event(s), after commit.

        The database delete is already authoritative (3.5.4); this only
        accelerates consumer cache eviction. Blacklists each captured access JTI
        with a TTL derived from its own expiry, revokes the matching refresh
        allowlist entry, and pushes the ``jti=None`` user-wide event so consumers
        flush every cached session for the user. The durable transactional outbox
        (:mod:`auth_user_service.services.outbox`) replaces this push on the
        **role-change** path only; the non-role-change revocation paths of 3.5.4
        keep the best-effort accelerator, because there the authoritative delete
        is the whole revocation and a lost push only delays cache eviction.

        ``user_wide=False`` narrows the eviction to the captured targets — one
        event per revoked JTI — for the administrative single-session path, whose
        blast radius is a single session rather than the user's whole lineage.
        """
        if redis is not None and targets:
            access_mgr = RedisSessionManager(redis)
            refresh_store = RedisRefreshStore(redis)
            now = datetime.now(timezone.utc)
            for target in targets:
                expires_at = target.expires_at
                if expires_at.tzinfo is None:
                    expires_at = expires_at.replace(tzinfo=timezone.utc)
                ttl = int((expires_at - now).total_seconds())
                if ttl > 0:
                    access_mgr.blacklist_jti(target.jti, ttl)
                refresh_store.revoke(target.jti)
        if not user_wide:
            for target in targets:
                emit(
                    EVENT_SESSION_REVOKED,
                    SessionRevokedEvent(
                        user_id=str(user_id), jti=target.jti
                    ).model_dump(),
                )
            return
        # jti=None signals "all of this user's sessions" — consumers flush every
        # cached session for the user rather than a single JTI.
        emit(
            EVENT_SESSION_REVOKED,
            SessionRevokedEvent(user_id=str(user_id), jti=None).model_dump(),
        )

    @staticmethod
    def revoke_session_record(
        session: Session,
        client_session: ClientSession,
        redis: Optional[Redis],
    ) -> None:
        """Administrative revocation of one session row (3.5.4).

        The row itself is already authoritative state, so the delete *is* the
        revocation; this adds the accelerator the administrative path previously
        lacked — without it a consumer's positive cache entry survived until its
        TTL even though the database had denied the session. Captures the JTI and
        its natural expiry before the delete, commits, then blacklists that one
        JTI, drops its refresh allowlist entry, and emits the per-JTI event.
        """
        target = RevocationTarget(
            jti=client_session.jwt_jti, expires_at=client_session.jwt_expires_at
        )
        user_id = str(client_session.user_id)
        session.delete(client_session)
        session.commit()
        SessionController.apply_post_commit_revocation(
            [target], user_id, redis, user_wide=False
        )

    @staticmethod
    def revoke_all_user_sessions(
        session: Session, user_id: Union[uuid.UUID, str], redis: Optional[Redis]
    ) -> int:
        """Revoke every active session for *user_id* — reuse-attack response.

        Convenience wrapper composing the transaction-neutral
        :meth:`capture_and_delete_user_sessions` with an owned commit and the
        post-commit accelerator, preserving the historical single-call behavior
        for the login reuse-attack path. Returns the number of sessions revoked.

        The access JTI and refresh JTI are the same value per token pair
        (``create_refresh_token`` is called with the access token's JTI), so
        ``ClientSession.jwt_jti`` covers both stores.

        Args:
            session: SQLModel DB session.
            user_id: String UUID of the compromised user.
            redis: Live Redis client, or None when Redis is unavailable.
        """
        targets, count = SessionController.capture_and_delete_user_sessions(
            session, user_id
        )
        session.commit()
        SessionController.apply_post_commit_revocation(targets, user_id, redis)
        return count
