"""Unit tests for core.db_utils helpers."""

from unittest.mock import MagicMock, patch

import pytest

from auth_user_service.core.db_utils import (
    DialectMismatchError,
    PrefixedBase,
    detect_connected_dialect,
    get_table_args,
    prefixed_fk,
    prefixed_tables,
    verify_selected_db_dialect,
)


class TestGetTableArgs:
    def test_mysql_returns_engine_and_charset(self):
        with patch("auth_user_service.core.db_utils.settings") as mock_settings:
            mock_settings.SELECTED_DB = "Mysql"
            mock_settings.DB_ENGINE = "InnoDB"
            mock_settings.DB_CHARSET = "utf8mb4"
            result = get_table_args()

        assert result == {"mysql_engine": "InnoDB", "mysql_charset": "utf8mb4"}

    def test_mariadb_returns_engine_and_charset(self):
        """ "Mariadb" shares the mysql_engine/mysql_charset table args (4.6)."""
        with patch("auth_user_service.core.db_utils.settings") as mock_settings:
            mock_settings.SELECTED_DB = "Mariadb"
            mock_settings.DB_ENGINE = "InnoDB"
            mock_settings.DB_CHARSET = "utf8mb4"
            result = get_table_args()

        assert result == {"mysql_engine": "InnoDB", "mysql_charset": "utf8mb4"}

    def test_postgres_returns_empty_dict(self):
        with patch("auth_user_service.core.db_utils.settings") as mock_settings:
            mock_settings.SELECTED_DB = "Postgres"
            result = get_table_args()

        assert result == {}

    def test_other_db_returns_empty_dict(self):
        with patch("auth_user_service.core.db_utils.settings") as mock_settings:
            mock_settings.SELECTED_DB = "SQLite"
            result = get_table_args()

        assert result == {}

    def test_mysql_custom_engine_and_charset(self):
        with patch("auth_user_service.core.db_utils.settings") as mock_settings:
            mock_settings.SELECTED_DB = "Mysql"
            mock_settings.DB_ENGINE = "MyISAM"
            mock_settings.DB_CHARSET = "latin1"
            result = get_table_args()

        assert result["mysql_engine"] == "MyISAM"
        assert result["mysql_charset"] == "latin1"


class TestPrefixedFk:
    def test_format_with_auth_prefix(self):
        with patch("auth_user_service.core.db_utils.settings") as mock_settings:
            mock_settings.TABLES_PREFIX = "auth"
            result = prefixed_fk("user", "id")

        assert result == "auth_user.id"

    def test_format_with_custom_prefix(self):
        with patch("auth_user_service.core.db_utils.settings") as mock_settings:
            mock_settings.TABLES_PREFIX = "myapp"
            result = prefixed_fk("session", "user_id")

        assert result == "myapp_session.user_id"

    def test_different_model_and_column(self):
        with patch("auth_user_service.core.db_utils.settings") as mock_settings:
            mock_settings.TABLES_PREFIX = "svc"
            result = prefixed_fk("api_key", "id")

        assert result == "svc_api_key.id"


class TestPrefixedTables:
    def test_format_with_auth_prefix(self):
        with patch("auth_user_service.core.db_utils.settings") as mock_settings:
            mock_settings.TABLES_PREFIX = "auth"
            result = prefixed_tables("user")

        assert result == "auth_user"

    def test_format_with_custom_prefix(self):
        with patch("auth_user_service.core.db_utils.settings") as mock_settings:
            mock_settings.TABLES_PREFIX = "myapp"
            result = prefixed_tables("api_key")

        assert result == "myapp_api_key"

    def test_format_with_multi_word_name(self):
        with patch("auth_user_service.core.db_utils.settings") as mock_settings:
            mock_settings.TABLES_PREFIX = "svc"
            result = prefixed_tables("client_session")

        assert result == "svc_client_session"


class TestPrefixedBase:
    def test_tablename_uses_prefix_and_lowercase_class_name(self):
        # Uses the real settings (TABLES_PREFIX="auth" from .env)
        class SomeWidget(PrefixedBase):
            pass

        assert SomeWidget.__tablename__ == "auth_somewidget"

    def test_tablename_multiword_class_is_lowercased(self):
        class MyComplexModel(PrefixedBase):
            pass

        assert MyComplexModel.__tablename__ == "auth_mycomplexmodel"


def _fake_connection(dialect_name: str, version_string: str = "") -> MagicMock:
    """A minimal stand-in for a SQLAlchemy ``Connection`` (4.6 dialect checks)."""
    conn = MagicMock()
    conn.dialect.name = dialect_name
    conn.exec_driver_sql.return_value.scalar.return_value = version_string
    return conn


class TestDetectConnectedDialect:
    def test_postgresql_dialect_detected_as_postgres(self):
        conn = _fake_connection("postgresql")

        assert detect_connected_dialect(conn) == "Postgres"
        conn.exec_driver_sql.assert_not_called()

    def test_mysql_server_version_detected_as_mysql(self):
        conn = _fake_connection("mysql", "8.4.10")

        assert detect_connected_dialect(conn) == "Mysql"

    def test_mariadb_server_version_detected_as_mariadb(self):
        conn = _fake_connection("mysql", "10.6.12-MariaDB-1:10.6.12+maria~ubu2004")

        assert detect_connected_dialect(conn) == "Mariadb"

    def test_mariadb_detection_is_case_insensitive(self):
        conn = _fake_connection("mysql", "5.5.5-10.11.6-MARIADB")

        assert detect_connected_dialect(conn) == "Mariadb"

    def test_unsupported_dialect_raises(self):
        conn = _fake_connection("sqlite")

        with pytest.raises(DialectMismatchError):
            detect_connected_dialect(conn)


class TestVerifySelectedDbDialect:
    """Every valid and invalid declared/actual engine combination (4.6)."""

    @pytest.mark.parametrize(
        "declared,dialect_name,version_string",
        [
            ("Postgres", "postgresql", ""),
            ("Mysql", "mysql", "8.4.10"),
            ("Mariadb", "mysql", "10.6.12-MariaDB"),
        ],
    )
    def test_matching_declaration_passes(self, declared, dialect_name, version_string):
        conn = _fake_connection(dialect_name, version_string)

        verify_selected_db_dialect(conn, declared)  # must not raise

    @pytest.mark.parametrize(
        "declared,dialect_name,version_string",
        [
            # Postgres declared against a MySQL-family server.
            ("Postgres", "mysql", "8.4.10"),
            ("Postgres", "mysql", "10.6.12-MariaDB"),
            # Mysql declared against Postgres or MariaDB.
            ("Mysql", "postgresql", ""),
            ("Mysql", "mysql", "10.6.12-MariaDB"),
            # Mariadb declared against Postgres or real MySQL.
            ("Mariadb", "postgresql", ""),
            ("Mariadb", "mysql", "8.4.10"),
        ],
    )
    def test_mismatched_declaration_raises(
        self, declared, dialect_name, version_string
    ):
        conn = _fake_connection(dialect_name, version_string)

        with pytest.raises(DialectMismatchError):
            verify_selected_db_dialect(conn, declared)
