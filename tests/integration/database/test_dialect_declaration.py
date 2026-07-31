"""Layer B: the 4.6 dialect-declaration contract against a real server.

The unit suite (``tests/core/db_utils_test.py``) proves the version-string
parsing logic with mocked connections; this module proves it against a
genuinely connected PostgreSQL, MySQL, or MariaDB server (whichever
``--database``/``FA_AUTH_IT_DIALECT`` selects), so the MariaDB-vs-MySQL
distinction is exercised on the real wire protocol, not an assumption about
what ``VERSION()`` returns. Run across all three matrix legs, this file
exercises every valid and invalid declared/actual engine combination in the
4.6 contract.
"""

from __future__ import annotations

import pytest
import sqlalchemy as sa

from auth_user_service.core.db_utils import (
    DialectMismatchError,
    detect_connected_dialect,
    verify_selected_db_dialect,
)
from tests.integration.database._engines import DIALECTS, EngineSpec

#: Every certified declaration, so mismatch cases can be derived per engine.
_ALL_DECLARATIONS = ("Postgres", "Mysql", "Mariadb")


def test_detected_dialect_matches_the_certified_declaration(
    it_engine: sa.Engine, engine_spec: EngineSpec
) -> None:
    """The real server is detected as exactly the engine the matrix selected."""
    with it_engine.connect() as conn:
        assert detect_connected_dialect(conn) == engine_spec.selected_db


def test_matching_declaration_passes(
    it_engine: sa.Engine, engine_spec: EngineSpec
) -> None:
    with it_engine.connect() as conn:
        verify_selected_db_dialect(conn, engine_spec.selected_db)  # must not raise


@pytest.mark.parametrize("wrong_declaration", _ALL_DECLARATIONS)
def test_every_mismatched_declaration_fails_closed(
    it_engine: sa.Engine, engine_spec: EngineSpec, wrong_declaration: str
) -> None:
    """Every declaration other than the real one raises, on every certified engine.

    Parametrized over all three declarations and skipping the true one turns
    this into full declared/actual coverage once the CI matrix runs the
    module on each of the three engines (4.6): PostgreSQL-vs-MySQL,
    PostgreSQL-vs-MariaDB, Mysql-vs-Postgres, Mysql-vs-MariaDB,
    Mariadb-vs-Postgres, and Mariadb-vs-Mysql are each covered by exactly one
    (engine, wrong_declaration) pair across the matrix.
    """
    if wrong_declaration == engine_spec.selected_db:
        pytest.skip("not a mismatch on this engine")

    with it_engine.connect() as conn, pytest.raises(DialectMismatchError):
        verify_selected_db_dialect(conn, wrong_declaration)


def test_matrix_covers_every_certified_dialect() -> None:
    """Locks the matrix key set this module's coverage claim depends on (4.6)."""
    assert set(DIALECTS) == {"postgresql", "mysql", "mariadb"}
