"""Tests for the CI AST guard banning direct ``is_superuser`` auth checks."""

from pathlib import Path

import pytest

from auth_user_service.scripts.check_no_direct_superuser_auth import (
    find_violations,
    iter_python_files,
    main,
    scan_paths,
)

_REPO_ROOT = Path(__file__).resolve().parents[2]
_SOURCE_ROOT = _REPO_ROOT / "auth_user_service"


class TestRealSourceIsClean:
    def test_no_violations_in_source_tree(self):
        assert scan_paths([_SOURCE_ROOT]) == []

    def test_main_returns_zero_on_clean_tree(self):
        assert main([str(_SOURCE_ROOT)]) == 0


class TestBannedDecisions:
    @pytest.mark.parametrize(
        "src",
        [
            "if user.is_superuser:\n    grant()\n",
            "if not current_user.is_superuser:\n    deny()\n",
            "allowed = base and user.is_superuser\n",
            "value = 1 if u.is_superuser else 0\n",
            "rows = [u for u in users if u.is_superuser]\n",
            "assert current_user.is_superuser\n",
            "while u.is_superuser:\n    step()\n",
        ],
    )
    def test_decision_reads_are_flagged(self, src):
        assert len(find_violations(src, "<snippet>")) == 1


class TestAllowedUsages:
    @pytest.mark.parametrize(
        "src",
        [
            "if has_superuser_privileges(u.role, u.is_superuser):\n    ok()\n",
            "validate_privilege_claims(role=r, is_superuser=u.is_superuser)\n",
            "privilege_claims_are_consistent(u.role, u.is_superuser)\n",
            "select(User).where(User.is_superuser)\n",
            "payload = dict(is_superuser=u.is_superuser)\n",
        ],
    )
    def test_predicate_args_and_serialization_are_allowed(self, src):
        assert find_violations(src, "<snippet>") == []


class TestCliAndScanning:
    def test_main_flags_a_violating_file(self, tmp_path, capsys):
        bad = tmp_path / "bad_module.py"
        bad.write_text("def guard(user):\n    return user.is_superuser or False\n")

        exit_code = main([str(bad)])

        assert exit_code == 1
        out = capsys.readouterr().out
        assert "is_superuser" in out
        assert "bad_module.py" in out

    def test_scan_paths_reports_line_and_snippet(self, tmp_path):
        bad = tmp_path / "guard.py"
        bad.write_text("x = 1\nif user.is_superuser:\n    pass\n")

        violations = scan_paths([tmp_path])

        assert len(violations) == 1
        assert violations[0].line == 2
        assert "is_superuser" in violations[0].snippet

    def test_iter_python_files_skips_pycache(self, tmp_path):
        pycache = tmp_path / "__pycache__"
        pycache.mkdir()
        (pycache / "stale.py").write_text("x = 1\n")
        real = tmp_path / "mod.py"
        real.write_text("x = 1\n")

        found = list(iter_python_files([tmp_path]))

        assert found == [real]

    def test_iter_python_files_ignores_non_python_file_argument(self, tmp_path):
        not_python = tmp_path / "notes.txt"
        not_python.write_text("hello\n")

        assert list(iter_python_files([not_python])) == []

    def test_main_defaults_to_source_package(self, monkeypatch):
        # No argv → defaults to scanning ``auth_user_service`` from repo root.
        monkeypatch.chdir(_REPO_ROOT)
        assert main([]) == 0
