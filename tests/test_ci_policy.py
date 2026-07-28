"""CI workflow policy tests — finding 11.7."""

import re
from pathlib import Path
from typing import Any

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = REPO_ROOT / ".github" / "workflows"
CI_YAML = WORKFLOWS / "CI.yaml"
DOCKER_PUBLISH_YAML = WORKFLOWS / "docker-publish.yaml"
DATABASE_YAML = WORKFLOWS / "database-integration.yaml"
EXAMPLE_SMOKE_YAML = WORKFLOWS / "example-smoke.yaml"

#: One maintained example per certified engine plus every distinct
#: signing/monitoring/hardening posture (§4.6) — the exact reassignment
#: decided for the 4.6 dialect-declaration contract.
MAINTAINED_EXAMPLES = {
    "quickstart_m8",
    "postgres_m8",
    "rs256_m8",
    "metrics_m8",
    "hardened_m8",
    "vault_dev_m8",
}

#: The exact pinned image of every certified dialect (supported database
#: contract, §4.6). MySQL and MariaDB are separate certified dialects: one never
#: certifies the other, so all three must appear.
CERTIFIED_IMAGES = {
    "postgresql": "postgres:18.4-alpine",
    "mysql": "mysql:8.4.10",
    "mariadb": "mariadb:12.3.2-ubi",
}

#: The single stable check branch protection points at. Renaming it silently
#: un-gates database-sensitive changes, so the name is locked by a test.
REQUIRED_CHECK_JOB = "database-matrix"

_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_USES_RE = re.compile(r"uses:\s+([a-zA-Z0-9_.\-]+/[a-zA-Z0-9_.\-]+@(\S+))")


def _load_yaml(path: Path) -> dict[str, Any]:
    with path.open() as fh:
        return yaml.safe_load(fh)  # type: ignore[no-any-return]


def _action_refs(path: Path) -> list[tuple[str, str]]:
    """Return (full-ref, sha-candidate) for every action ``uses:`` in a workflow."""
    results: list[tuple[str, str]] = []
    for m in _USES_RE.finditer(path.read_text()):
        full_ref = m.group(1)
        sha_part = m.group(2).split("#")[0].strip()
        results.append((full_ref, sha_part))
    return results


# ── 11.7  CI workflow consolidation — one canonical gate ────────────────────


def test_no_duplicate_ci_yml() -> None:
    """ci.yml must not exist — CI.yaml is the single canonical quality gate."""
    assert not (WORKFLOWS / "ci.yml").exists(), (
        "Found duplicate ci.yml; the canonical workflow is CI.yaml."
    )


def test_ci_yaml_has_secret_scan_job() -> None:
    """CI.yaml must contain the gitleaks secret-scan job."""
    wf = _load_yaml(CI_YAML)
    assert "secret-scan" in wf["jobs"], "CI.yaml must include a secret-scan job."


def test_ci_yaml_actions_are_sha_pinned() -> None:
    """Every action reference in CI.yaml must be pinned to a full 40-char commit SHA."""
    refs = _action_refs(CI_YAML)
    assert refs, "No action references found in CI.yaml."
    for full_ref, sha_part in refs:
        assert _SHA_RE.match(sha_part), (
            f"CI.yaml: '{full_ref}' is not SHA-pinned — use a full 40-char commit hash."
        )


def test_docker_publish_yaml_actions_are_sha_pinned() -> None:
    """Every action reference in docker-publish.yaml must be pinned to a full 40-char commit SHA."""
    refs = _action_refs(DOCKER_PUBLISH_YAML)
    assert refs, "No action references found in docker-publish.yaml."
    for full_ref, sha_part in refs:
        assert _SHA_RE.match(sha_part), (
            f"docker-publish.yaml: '{full_ref}' is not SHA-pinned — use a full 40-char commit hash."
        )


# ── Phase 7 — flag-only-authorization ban covers the maintained example ────


def test_ci_yaml_bans_direct_superuser_auth_in_bundled_example() -> None:
    """The is_superuser AST guard must also scan examples/fastapi_full.

    ``check_no_direct_superuser_auth`` previously ran against
    ``auth_user_service`` only, so a flag-only authorization check in the
    maintained example (``examples/fastapi_full``) shipped unflagged. This
    locks the CI invocation so the scan scope cannot silently regress back to
    the issuer package alone.
    """
    text = CI_YAML.read_text()
    assert (
        "check_no_direct_superuser_auth auth_user_service examples/fastapi_full" in text
    ), (
        "CI.yaml must run check_no_direct_superuser_auth against both "
        "auth_user_service and examples/fastapi_full."
    )


# ── Phase 7 — the bundled example's own unit suite is gated ────────────────


def test_ci_yaml_runs_the_bundled_example_unit_tests() -> None:
    """The example's ownership/authorization rules must be gated by CI.

    ``pytest`` at the repo root has ``testpaths = tests`` and measures
    ``auth_user_service`` only, so ``examples/fastapi_full/tests`` (the
    ownership-preservation suite) runs solely through its own pytest config in
    a dedicated job. This locks that job so the suite cannot silently stop
    running.
    """
    wf = _load_yaml(CI_YAML)
    assert "example-tests" in wf["jobs"], (
        "CI.yaml must include the example-tests job running the bundled "
        "fastapi_full unit suite."
    )
    assert (
        "pytest -c examples/fastapi_full/pytest.ini examples/fastapi_full/tests"
        in CI_YAML.read_text()
    ), (
        "CI.yaml's example-tests job must run the bundled example suite through "
        "examples/fastapi_full/pytest.ini."
    )


# ── Layer B database integration matrix (TEST-DB-01 / TEST-LAYER-01, §4.6) ──


def test_database_integration_workflow_exists() -> None:
    """The three-dialect matrix must be wired, not merely writable by hand."""
    assert DATABASE_YAML.exists(), (
        "The Layer B database integration matrix (TEST-DB-01) must run in CI; "
        "expected .github/workflows/database-integration.yaml."
    )


def test_database_integration_actions_are_sha_pinned() -> None:
    refs = _action_refs(DATABASE_YAML)
    assert refs, "No action references found in database-integration.yaml."
    for full_ref, sha_part in refs:
        assert _SHA_RE.match(sha_part), (
            f"database-integration.yaml: '{full_ref}' is not SHA-pinned — "
            "use a full 40-char commit hash."
        )


def test_database_matrix_covers_every_certified_dialect_at_its_pinned_version() -> None:
    """All three engines, each at the exact version the contract certifies.

    A release must not proceed while any supported dialect fails (§4.6), and a
    version pin that drifts silently would mean the matrix certifies something
    other than what deployments run.
    """
    wf = _load_yaml(DATABASE_YAML)
    entries = wf["jobs"]["matrix"]["strategy"]["matrix"]["include"]
    covered = {entry["database"]: entry["image"] for entry in entries}
    assert covered == CERTIFIED_IMAGES, (
        "The Layer B matrix must cover exactly PostgreSQL, MySQL, and MariaDB "
        f"at their pinned versions ({CERTIFIED_IMAGES}); found {covered}."
    )


def test_database_matrix_does_not_fail_fast() -> None:
    """Every dialect's result is evidence; one failure must not cancel the rest."""
    wf = _load_yaml(DATABASE_YAML)
    assert wf["jobs"]["matrix"]["strategy"]["fail-fast"] is False


def test_one_stable_aggregate_check_reports_for_branch_protection() -> None:
    """The required check exists, always runs, and passes when path-filtered out.

    Branch protection needs a check that reports on *every* pull request; a job
    that is skipped when no database-sensitive file changed would leave the
    check pending forever.
    """
    wf = _load_yaml(DATABASE_YAML)
    aggregate = wf["jobs"][REQUIRED_CHECK_JOB]
    assert aggregate["if"] is True or str(aggregate["if"]).strip() == "always()", (
        f"The {REQUIRED_CHECK_JOB} job must run with if: always() so the "
        "required check always reports."
    )
    assert set(aggregate["needs"]) == {"scope", "matrix"}
    body = DATABASE_YAML.read_text()
    assert 'if [ "$RUN_MATRIX" != "true" ]' in body, (
        "The aggregate check must report success when path filtering decided no "
        "database-sensitive file changed."
    )
    assert 'if [ "$MATRIX_RESULT" != "success" ]' in body, (
        "The aggregate check must fail when the three-dialect matrix did not pass."
    )


def test_full_matrix_runs_on_main_nightly_and_release() -> None:
    """Path filtering narrows pull requests only — never the release gate."""
    wf = _load_yaml(DATABASE_YAML)
    # PyYAML parses the bare key ``on`` as the boolean True.
    triggers = wf[True] if True in wf else wf["on"]
    assert "schedule" in triggers, "the nightly full matrix trigger is missing"
    assert "release" in triggers, "the release full matrix trigger is missing"
    assert "main" in triggers["push"]["branches"]
    body = DATABASE_YAML.read_text()
    assert '"$EVENT_NAME" != "pull_request"' in body, (
        "Non-pull-request events must bypass path filtering and run the "
        "complete matrix (4.6)."
    )


def test_unit_gate_stays_docker_free() -> None:
    """``TEST-LAYER-01``: the 100% unit gate must need no database service.

    A service container attached to the unit job would make the Docker-free
    guarantee — and a developer's ability to reach the coverage gate offline —
    quietly untrue.
    """
    wf = _load_yaml(CI_YAML)
    assert "services" not in wf["jobs"]["test"], (
        "The unit test job must not depend on a database service container."
    )
    assert "database_integration" not in CI_YAML.read_text(), (
        "The Layer B suite must not run inside the Docker-free unit workflow."
    )


# ── Maintained-example smoke automation (§4.6, TEST-LAYER-01) ───────────────


def test_example_smoke_workflow_exists() -> None:
    """The maintained-example smoke flow must be wired, not merely documented."""
    assert EXAMPLE_SMOKE_YAML.exists(), (
        "The maintained-example smoke flow (§4.6) must run in CI; expected "
        ".github/workflows/example-smoke.yaml."
    )


def test_example_smoke_actions_are_sha_pinned() -> None:
    refs = _action_refs(EXAMPLE_SMOKE_YAML)
    assert refs, "No action references found in example-smoke.yaml."
    for full_ref, sha_part in refs:
        assert _SHA_RE.match(sha_part), (
            f"example-smoke.yaml: '{full_ref}' is not SHA-pinned — use a full "
            "40-char commit hash."
        )


def test_example_smoke_covers_every_maintained_example() -> None:
    """Every maintained compose example is exercised — no silent drop (§4.6)."""
    wf = _load_yaml(EXAMPLE_SMOKE_YAML)
    covered = set(wf["jobs"]["smoke"]["strategy"]["matrix"]["example"])
    assert covered == MAINTAINED_EXAMPLES, (
        f"example-smoke.yaml must cover exactly {MAINTAINED_EXAMPLES}; found {covered}."
    )


def test_example_smoke_does_not_fail_fast() -> None:
    """One example failing to start must not hide the others' results."""
    wf = _load_yaml(EXAMPLE_SMOKE_YAML)
    assert wf["jobs"]["smoke"]["strategy"]["fail-fast"] is False


def test_example_smoke_aggregate_check_always_reports() -> None:
    """The required check exists and always runs, mirroring the Layer B gate."""
    wf = _load_yaml(EXAMPLE_SMOKE_YAML)
    aggregate = wf["jobs"]["example-smoke"]
    assert aggregate["if"] is True or str(aggregate["if"]).strip() == "always()", (
        "The example-smoke aggregate job must run with if: always() so the "
        "required check always reports."
    )
    assert aggregate["needs"] == "smoke"


def test_example_smoke_runs_on_main_nightly_and_release() -> None:
    """Every maintained example is exercised on main/nightly/release (§4.6)."""
    wf = _load_yaml(EXAMPLE_SMOKE_YAML)
    triggers = wf[True] if True in wf else wf["on"]
    assert "schedule" in triggers, "the nightly full smoke-run trigger is missing"
    assert "release" in triggers, "the release smoke-run trigger is missing"
    assert "main" in triggers["push"]["branches"]


def test_layer_b_is_excluded_from_the_default_pytest_run() -> None:
    """The default suite stays Docker-free by configuration, not by convention."""
    pytest_ini = (REPO_ROOT / "pytest.ini").read_text()
    assert '-m "not database_integration"' in pytest_ini, (
        "pytest.ini must deselect the database_integration marker by default so "
        "the unit gate never requires Docker."
    )
    assert "database_integration:" in pytest_ini, (
        "The database_integration marker must be registered (--strict-markers)."
    )
