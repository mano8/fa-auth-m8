"""
Users Controller
"""

import uuid
from dataclasses import dataclass
from typing import Any, Optional
from sqlmodel import Session, func, select
from auth_user_service.core.security import SecurityHelper
from auth_user_service.db_models.users import User, UserCreate, UserUpdate
from auth_user_service.services.generation import GenerationController
from auth_sdk_m8.schemas.base import AuthProviderType, RoleType

# Explicit allowlist for admin user updates — includes role, never includes
# is_superuser (server-derived) nor is_active (an authorization-state transition
# owned exclusively by the route-owned transaction in ``services.role_admin``,
# which must revoke sessions/keys under the superuser-set lock — never a bare
# field write here).
_ADMIN_UPDATE_FIELDS: frozenset[str] = frozenset(
    {"email", "full_name", "avatar", "role", "oauth_user_id", "hashed_password"}
)


@dataclass(frozen=True)
class UserUpdateOutcome:
    """What an in-memory :meth:`UserController.apply_user_update` changed.

    ``role_changed`` is the authorization-state signal the caller uses to decide
    whether to bump the generation and revoke sessions; ``previous_role`` is
    captured before the mutation so the route-owned transaction can evaluate the
    role-administration matrix and the last-superuser predicate.
    """

    previous_role: RoleType
    new_role: RoleType
    role_changed: bool


def _derive_is_superuser(role: RoleType) -> bool:
    """Derive the ``is_superuser`` flag from the authorized role.

    The flag is server-derived evidence of the canonical role, never a
    client-submitted permission switch: ``SUPERADMIN -> True``, every other
    role -> ``False``. This is the single derivation point shared by the create
    and update paths, keeping the persisted pair consistent with the DB check
    constraint and the model invariant.
    """
    return role == RoleType.SUPERADMIN


class UserController:
    """User Controller"""

    @staticmethod
    def build_user(*, session: Session, user_create: UserCreate) -> User:
        """Persist a new user in the caller's transaction — **no commit** (3.5).

        Transaction-neutral internal mirroring :meth:`create_user` but leaving the
        commit to the caller, so a privileged create route can enqueue its audit
        row in the *same* transaction (Phase 7): the user row and its audit row
        commit together or not at all. The id is generated in-process, so it is
        known to the caller for the audit row before the flush.

        Args:
            session (Session): The database session that owns the transaction.
            user_create (UserCreate): The details of the user to be created.

        Returns:
            User: The newly built user object, flushed but not committed.

        Raises:
            ValueError: password-based registration without a password.
        """
        # Derive the privilege flag server-side from the role; any client-supplied
        # is_superuser on the create payload is ignored (never authoritative).
        derived_is_superuser = _derive_is_superuser(user_create.role)
        if user_create.provider == AuthProviderType.PASSWORD:
            if user_create.password is None:
                raise ValueError("password is required for password-based registration")
            db_obj = User.model_validate(
                user_create,
                update={
                    "hashed_password": SecurityHelper.get_password_hash(
                        user_create.password
                    ),
                    "id": str(uuid.uuid4()),
                    "is_superuser": derived_is_superuser,
                },
            )
        else:
            db_obj = User.model_validate(
                user_create,
                update={
                    "id": str(uuid.uuid4()),
                    "is_superuser": derived_is_superuser,
                },
            )
        session.add(db_obj)
        session.flush()
        return db_obj

    @staticmethod
    def create_user(*, session: Session, user_create: UserCreate) -> User:
        """
        Create a new user in the database.

        Convenience wrapper composing the transaction-neutral :meth:`build_user`
        with an owned commit, preserving the historical single-call behavior for
        callers that do not compose an audit row (init/OAuth/self-service paths).

        Args:
            session (Session):
                The database session to use for the operation.
            user_create (UserCreate):
                An object containing the details of the user to be created.

        Returns:
            User: The newly created user object.

        Raises:
            SQLAlchemyError:
                If there is an error during the database operation.
        """
        db_obj = UserController.build_user(session=session, user_create=user_create)
        session.commit()
        session.refresh(db_obj)
        return db_obj

    @staticmethod
    def apply_user_update(*, db_user: User, user_in: UserUpdate) -> UserUpdateOutcome:
        """Apply allowlisted update fields to *db_user* in memory only.

        Transaction-neutral internal (3.5): it mutates the tracked ORM object
        and re-derives the server-owned ``is_superuser`` flag, but it does **not**
        commit, bump the generation, or revoke anything. The route-owned
        transaction (``services.role_admin``) composes it so the flag derivation,
        generation bump, session/API-key revocation, and commit all happen once
        under the superuser-set lock; the convenience wrapper
        :meth:`update_user` composes it for ordinary non-authorization edits.

        ``is_active`` is intentionally not in the allowlist — activation
        transitions are authorization-state changes owned by the route-owned
        transaction, never a bare field write here.
        """
        previous_role = db_user.role
        user_data = user_in.model_dump(exclude_unset=True)
        extra_data: dict[str, Any] = {}
        if "password" in user_data:
            extra_data["hashed_password"] = SecurityHelper.get_password_hash(
                user_data["password"]
            )
        for field, value in {**user_data, **extra_data}.items():
            if field in _ADMIN_UPDATE_FIELDS:
                setattr(db_user, field, value)
        # Re-derive the privilege flag from the (possibly updated) role, outside
        # the allowlist loop so it can never be set from a client-supplied field.
        if "role" in user_data:
            db_user.is_superuser = _derive_is_superuser(db_user.role)
        return UserUpdateOutcome(
            previous_role=previous_role,
            new_role=db_user.role,
            role_changed=db_user.role != previous_role,
        )

    @staticmethod
    def update_user(*, session: Session, db_user: User, user_in: UserUpdate) -> Any:
        """
        Update an existing user in the database (convenience wrapper).

        Ordinary callers that only touch non-authorization fields (or need the
        historical single-call role-change behavior outside the superuser-set
        transaction) use this wrapper; it composes the transaction-neutral
        :meth:`apply_user_update` and owns the commit. A real role change is an
        authorization-state transition, so the generation is bumped
        transactionally (3.5.1) — a same-role update is a no-op for revocation
        here. A mismatched-flag row is not repaired through this wrapper: the
        audited repair command owns that path
        (:mod:`auth_user_service.services.security_preflight`), and it propagates
        the generation, event, and cache eviction exactly like a runtime change.

        Args:
            session (Session): The database session to use for the update.
            db_user (User): The existing user object to be updated.
            user_in (UserUpdate): The new data for the user.

        Returns:
            Any: The updated user object.
        """
        outcome = UserController.apply_user_update(db_user=db_user, user_in=user_in)
        if outcome.role_changed:
            GenerationController.bump_user_generation(db_user)
        session.add(db_user)
        session.commit()
        session.refresh(db_user)
        return db_user

    @staticmethod
    def get_user(*, session: Session, user_id: uuid.UUID) -> Optional[User]:
        """
        Retrieve a user from the database by their ID.

        Args:
            session (Session): The database session to use for the query.
            user_id (uuid.UUID): The unique identifier of the user to retrieve.

        Returns:
            User | None: The user object if found, otherwise None.
        """
        statement = select(User).where(User.id == user_id)
        session_user = session.exec(statement).first()
        return session_user

    @staticmethod
    def get_user_by_email(*, session: Session, email: str) -> Optional[User]:
        """
        Retrieve a user from the database by their email address.

        Args:
            session (Session): The database session to use for the query.
            email (str): The email address of the user to retrieve.

        Returns:
            User | None: The user object if found, otherwise None.
        """
        statement = select(User).where(User.email == email)
        session_user = session.exec(statement).first()
        return session_user

    @staticmethod
    def count_users(*, session: Session) -> int:
        """
        Count users present.

        Args:
            session (Session): The database session to use for the query.

        Returns:
            int: Number of users in data base
        """
        statement = select(func.count()).select_from(User)
        return session.exec(statement).one()
