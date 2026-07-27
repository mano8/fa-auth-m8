from typing import List, Optional
import uuid
from pydantic import ConfigDict, model_validator
from sqlalchemy import UniqueConstraint
from sqlmodel import CHAR, Column, Field, SQLModel
from slugify import slugify

from fastapi_m8 import TimestampMixin
from fastapi_full.core.db_models import prefixed_tables
from fastapi_full.core.config import settings


# ---------------------------------------------------------------
# ---------------------------------------------------------------
# ------- Category
# ---------------------------------------------------------------
# ---------------------------------------------------------------
class CategoryBase(SQLModel):
    """
    Shared fields for category schemas.
    """

    name: str = Field(
        unique=True,
        min_length=1,
        max_length=50,
        description="Category name",
    )
    slug: str = Field(
        unique=True,
        min_length=1,
        max_length=50,
        description="URL-friendly identifier",
    )


class CategoryGenerators(CategoryBase):
    """
    Category schema with slug auto-generation.
    """

    @model_validator(mode="before")
    @classmethod
    def generate_slug(cls, values):
        """
        Auto-generate `slug` from the `name` field.
        """
        name = values.get("name")
        if name:
            values["slug"] = slugify(values.get("name"))
        return values


class CategoryCreate(CategoryGenerators):
    """
    Schema for creating a new category.

    ``extra="forbid"`` is what makes ownership preservation an enforced rule
    rather than an accident of the field list: a body carrying ``owner_id`` is
    rejected outright instead of being silently ignored. The only ownership
    input a client may send is ``target_owner_id``, the explicit superadmin
    cross-owner request resolved by ``app.ownership.resolve_create_owner_id``.
    """

    model_config = ConfigDict(extra="forbid")  # type: ignore[assignment]

    target_owner_id: Optional[uuid.UUID] = Field(
        default=None,
        description=(
            "Create this category on behalf of another user. Canonical "
            "superusers only; must resolve to an existing user."
        ),
    )


class CategoryUpdate(CategoryGenerators):
    """
    Schema for updating an existing category.

    An edit never changes ownership, so it accepts no ownership field at all:
    ``extra="forbid"`` rejects ``owner_id`` and ``target_owner_id`` alike, and
    the edit operates on the ``owner_id`` already persisted on the fetched row.
    """

    model_config = ConfigDict(extra="forbid")  # type: ignore[assignment]


class Category(TimestampMixin, CategoryBase, SQLModel, table=True):
    """
    Database model for a category.
    """

    __tablename__ = prefixed_tables("category")
    __table_args__ = (
        UniqueConstraint("slug", name="uq_category_slug"),
        {"mysql_engine": settings.DB_ENGINE, "mysql_charset": settings.DB_CHARSET},
    )
    id: int = Field(
        default=None,
        primary_key=True,
        index=True,
        description="Category ID",
    )
    owner_id: uuid.UUID = Field(
        sa_column=Column("owner_id", CHAR(36), nullable=False, index=True),
        description="ID of the user who owns this category",
    )


class CategoryPublic(CategoryBase, SQLModel):
    """
    Public representation of a category.
    """

    id: int = Field(
        description="Category ID",
    )
    owner_id: uuid.UUID = Field(
        description="ID of the user who owns this category",
    )


class CategoriesPublic(SQLModel):
    """
    Wrapper for a list of public categories.
    """

    data: List[CategoryPublic] = Field(
        description="List of categories",
    )
    count: int = Field(
        description="Total categories count",
    )


def build_category(item_in: CategoryCreate, *, owner_id: uuid.UUID) -> Category:
    """Build a persistable ``Category`` whose owner comes only from *owner_id*.

    Only the content fields are copied across, so no request body can reach the
    ownership column — not through ``owner_id`` (rejected by the schema) and
    not through ``target_owner_id`` (an input to the ownership rules, never a
    persisted value).

    Args:
        item_in: The validated creation payload.
        owner_id: The owner resolved by ``app.ownership.resolve_create_owner_id``.

    Returns:
        The unsaved ``Category`` row.
    """
    return Category(name=item_in.name, slug=item_in.slug, owner_id=owner_id)
