"""
Users Controller
"""

import uuid
from typing import Any, Optional
from sqlmodel import Session, func, select
from auth_user_service.core.security import SecurityHelper
from auth_user_service.db_models.users import User, UserCreate, UserUpdate
from auth_user_service.services.generation import GenerationController
from auth_sdk_m8.schemas.base import AuthProviderType, RoleType

# Explicit allowlist for admin user updates — includes role, never includes is_superuser.
_ADMIN_UPDATE_FIELDS: frozenset[str] = frozenset(
    {"email", "full_name", "avatar", "role", "oauth_user_id", "hashed_password"}
)


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
    def create_user(*, session: Session, user_create: UserCreate) -> User:
        """
        Create a new user in the database.

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
        session.commit()
        session.refresh(db_obj)
        return db_obj

    @staticmethod
    def update_user(*, session: Session, db_user: User, user_in: UserUpdate) -> Any:
        """
        Update an existing user in the database.

        Args:
            session (Session): The database session to use for the update.
            db_user (User): The existing user object to be updated.
            user_in (UserUpdate): The new data for the user.

        Returns:
            Any: The updated user object.

        Notes:
            - If the `user_in` contains a password, it will be hashed
            and stored in the `hashed_password` field.
            - The function commits the changes to the database
            and refreshes the `db_user` object.
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
        # A real role change is an authorization-state transition: bump the
        # generation transactionally so every session issued under the prior role
        # is detectably stale (3.5.1). A same-role update is not a transition here
        # (the full repair-path handling of a mismatched-flag row is a later plan
        # item); the flag is already re-derived above regardless.
        if db_user.role != previous_role:
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
