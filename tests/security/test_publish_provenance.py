"""Structural tests for the Docker publish workflow (plan item 4.2).

Asserts that `docker-publish.yaml` contains all required supply-chain
hardening steps — SBOM generation, keyless cosign signing, CVE-gated Trivy
scan, and release artifact upload — without actually running the workflow.

Rules asserted here:
- CRITICAL/HIGH Trivy scan is present and blocks push (exit-code "1").
- A non-blocking JSON Trivy scan is present for release artifact attachment.
- SBOM generation step uses anchore/sbom-action.
- A cosign signing step runs after push (skipped on workflow_dispatch).
- The publish job declares `id-token: write` (required for keyless OIDC).
- The publish job declares `contents: write` (required for release upload).
- SBOM and Trivy JSON are uploaded as release assets on the release event.
- The multi-arch build-push step has `provenance: mode=max`.
- cosign and SBOM steps are skipped / gated on `workflow_dispatch` correctly.

No Docker or network access required; everything is parsed from the YAML file.
"""

from __future__ import annotations

from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "docker-publish.yaml"


def _load_workflow() -> dict:
    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))


def _job_steps(workflow: dict, job_id: str = "build-and-push") -> list[dict]:
    return workflow["jobs"][job_id]["steps"]


def _job_permissions(workflow: dict, job_id: str = "build-and-push") -> dict:
    return workflow["jobs"][job_id].get("permissions", {})


def _steps_with_uses(steps: list[dict], prefix: str) -> list[dict]:
    return [s for s in steps if s.get("uses", "").startswith(prefix)]


def _steps_with_name(steps: list[dict], fragment: str) -> list[dict]:
    return [s for s in steps if fragment.lower() in s.get("name", "").lower()]


# ---------------------------------------------------------------------------
# Permissions
# ---------------------------------------------------------------------------


def test_id_token_write_permission() -> None:
    """Keyless cosign OIDC signing requires id-token: write."""
    perms = _job_permissions(_load_workflow())
    assert perms.get("id-token") == "write", (
        "docker-publish.yaml job must declare 'id-token: write' "
        "so cosign can request a GitHub OIDC token for keyless signing"
    )


def test_contents_write_permission() -> None:
    """Uploading release assets requires contents: write."""
    perms = _job_permissions(_load_workflow())
    assert perms.get("contents") == "write", (
        "docker-publish.yaml job must declare 'contents: write' "
        "to upload SBOM and scan reports as release assets"
    )


# ---------------------------------------------------------------------------
# Trivy gate (blocking scan — must exit-code "1" on CRITICAL/HIGH)
# ---------------------------------------------------------------------------


def test_trivy_blocking_scan_present() -> None:
    """A Trivy step with exit-code '1' (blocks push) must be present."""
    steps = _job_steps(_load_workflow())
    trivy_steps = _steps_with_uses(steps, "aquasecurity/trivy-action")
    blocking = [s for s in trivy_steps if s.get("with", {}).get("exit-code") == "1"]
    assert blocking, (
        "No blocking Trivy step found (exit-code: '1'); "
        "releases must be gated on CRITICAL/HIGH CVEs"
    )


def test_trivy_blocking_scan_targets_critical_high() -> None:
    """The blocking Trivy scan must target CRITICAL and HIGH severities."""
    steps = _job_steps(_load_workflow())
    trivy_steps = _steps_with_uses(steps, "aquasecurity/trivy-action")
    blocking = [s for s in trivy_steps if s.get("with", {}).get("exit-code") == "1"]
    assert blocking, "No blocking Trivy step found"
    sev = blocking[0]["with"].get("severity", "")
    assert "CRITICAL" in sev and "HIGH" in sev, (
        f"Blocking Trivy step severity '{sev}' must include CRITICAL and HIGH"
    )


# ---------------------------------------------------------------------------
# Trivy JSON scan (non-blocking — release artifact)
# ---------------------------------------------------------------------------


def test_trivy_json_scan_present() -> None:
    """A non-blocking JSON Trivy scan must exist to produce a release artifact."""
    steps = _job_steps(_load_workflow())
    trivy_steps = _steps_with_uses(steps, "aquasecurity/trivy-action")
    json_scans = [
        s
        for s in trivy_steps
        if s.get("with", {}).get("format") == "json"
        and s.get("with", {}).get("exit-code") == "0"
    ]
    assert json_scans, (
        "No non-blocking Trivy JSON scan step found; "
        "a JSON-format Trivy step (exit-code: '0') is required to produce "
        "a scan report for release artifact attachment"
    )


def test_trivy_json_scan_writes_output_file() -> None:
    """The Trivy JSON scan must write its output to a file."""
    steps = _job_steps(_load_workflow())
    trivy_steps = _steps_with_uses(steps, "aquasecurity/trivy-action")
    json_scans = [s for s in trivy_steps if s.get("with", {}).get("format") == "json"]
    assert json_scans, "No JSON Trivy step found"
    assert json_scans[0]["with"].get("output"), (
        "Trivy JSON scan step must set 'output:' to write results to a file"
    )


# ---------------------------------------------------------------------------
# SBOM generation
# ---------------------------------------------------------------------------


def test_sbom_generation_step_present() -> None:
    """An anchore/sbom-action step must be present to generate the SBOM."""
    steps = _job_steps(_load_workflow())
    sbom_steps = _steps_with_uses(steps, "anchore/sbom-action")
    assert sbom_steps, (
        "No anchore/sbom-action step found in docker-publish.yaml; "
        "SBOM generation is required for supply-chain provenance"
    )


def test_sbom_uses_spdx_format() -> None:
    """The SBOM must be generated in SPDX JSON format."""
    steps = _job_steps(_load_workflow())
    sbom_steps = _steps_with_uses(steps, "anchore/sbom-action")
    assert sbom_steps, "No SBOM step found"
    fmt = sbom_steps[0].get("with", {}).get("format", "")
    assert "spdx" in fmt.lower(), (
        f"SBOM step format '{fmt}' should be spdx-json for broad toolchain compatibility"
    )


def test_sbom_writes_output_file() -> None:
    """The SBOM step must write an output file for release upload."""
    steps = _job_steps(_load_workflow())
    sbom_steps = _steps_with_uses(steps, "anchore/sbom-action")
    assert sbom_steps, "No SBOM step found"
    assert sbom_steps[0].get("with", {}).get("output-file"), (
        "anchore/sbom-action step must set 'output-file:' to produce a downloadable SBOM"
    )


# ---------------------------------------------------------------------------
# Cosign signing
# ---------------------------------------------------------------------------


def test_cosign_installer_step_present() -> None:
    """sigstore/cosign-installer must be present for keyless image signing."""
    steps = _job_steps(_load_workflow())
    cosign_steps = _steps_with_uses(steps, "sigstore/cosign-installer")
    assert cosign_steps, (
        "No sigstore/cosign-installer step found in docker-publish.yaml; "
        "image signing with OIDC provenance is required"
    )


def test_cosign_installer_skipped_on_workflow_dispatch() -> None:
    """cosign install must be skipped on workflow_dispatch (no push → nothing to sign)."""
    steps = _job_steps(_load_workflow())
    cosign_steps = _steps_with_uses(steps, "sigstore/cosign-installer")
    assert cosign_steps, "No cosign-installer step found"
    cond = cosign_steps[0].get("if", "")
    assert "workflow_dispatch" in cond, (
        f"cosign-installer step 'if:' condition '{cond}' must skip on workflow_dispatch"
    )


def test_cosign_sign_step_present() -> None:
    """A step running `cosign sign` must exist after the push step."""
    steps = _job_steps(_load_workflow())
    sign_steps = [s for s in steps if "cosign sign" in s.get("run", "")]
    assert sign_steps, (
        "No 'cosign sign' run step found in docker-publish.yaml; "
        "the published image digest must be signed for supply-chain integrity"
    )


def test_cosign_sign_uses_yes_flag() -> None:
    """`cosign sign --yes` prevents interactive prompts in CI."""
    steps = _job_steps(_load_workflow())
    sign_steps = [s for s in steps if "cosign sign" in s.get("run", "")]
    assert sign_steps, "No cosign sign step found"
    assert "--yes" in sign_steps[0]["run"], (
        "cosign sign must include '--yes' to suppress interactive prompts in CI"
    )


def test_cosign_sign_skipped_on_workflow_dispatch() -> None:
    """cosign sign must be skipped on workflow_dispatch (no image is pushed)."""
    steps = _job_steps(_load_workflow())
    sign_steps = [s for s in steps if "cosign sign" in s.get("run", "")]
    assert sign_steps, "No cosign sign step found"
    cond = sign_steps[0].get("if", "")
    assert "workflow_dispatch" in cond, (
        f"cosign sign step 'if:' condition '{cond}' must skip on workflow_dispatch"
    )


# ---------------------------------------------------------------------------
# Provenance in multi-arch build-push
# ---------------------------------------------------------------------------


def test_build_push_step_has_provenance() -> None:
    """The multi-arch build-push step must set provenance: mode=max."""
    steps = _job_steps(_load_workflow())
    push_steps = [
        s
        for s in steps
        if s.get("uses", "").startswith("docker/build-push-action")
        and s.get("with", {}).get("push") is not None
        and "multi" in s.get("name", "").lower()
    ]
    if not push_steps:
        # Fallback: find the step with multi-arch platforms
        push_steps = [
            s
            for s in steps
            if s.get("uses", "").startswith("docker/build-push-action")
            and "arm64" in str(s.get("with", {}).get("platforms", ""))
        ]
    assert push_steps, "No multi-arch build-push step found"
    provenance = push_steps[0].get("with", {}).get("provenance", "")
    assert "max" in str(provenance).lower(), (
        f"Multi-arch build-push step provenance '{provenance}' must be 'mode=max' "
        "to attach a full provenance attestation to the OCI manifest"
    )


# ---------------------------------------------------------------------------
# Release artifact upload
# ---------------------------------------------------------------------------


def test_sbom_uploaded_to_release() -> None:
    """A step must upload the SBOM file to the GitHub Release."""
    steps = _job_steps(_load_workflow())
    upload_steps = [
        s
        for s in steps
        if "sbom" in s.get("run", "").lower() and "release" in s.get("run", "").lower()
    ]
    assert upload_steps, (
        "No step uploads the SBOM to the GitHub Release; "
        "the SBOM must be attached as a release asset so consumers can verify provenance"
    )


def test_sbom_upload_gated_on_release_event() -> None:
    """SBOM release upload must only run on 'release' events, not workflow_dispatch."""
    steps = _job_steps(_load_workflow())
    upload_steps = [
        s
        for s in steps
        if "sbom" in s.get("run", "").lower() and "release" in s.get("run", "").lower()
    ]
    assert upload_steps, "No SBOM release upload step found"
    cond = upload_steps[0].get("if", "")
    assert "release" in cond, (
        f"SBOM upload step 'if:' condition '{cond}' must be gated on the release event"
    )


def test_trivy_report_uploaded_to_release() -> None:
    """A step must upload the Trivy JSON report to the GitHub Release."""
    steps = _job_steps(_load_workflow())
    upload_steps = [
        s
        for s in steps
        if "trivy" in s.get("run", "").lower() and "release" in s.get("run", "").lower()
    ]
    assert upload_steps, (
        "No step uploads the Trivy scan report to the GitHub Release; "
        "scan results must be attached as a release asset for auditability"
    )


def test_trivy_report_upload_gated_on_release_event() -> None:
    """Trivy report release upload must only run on 'release' events."""
    steps = _job_steps(_load_workflow())
    upload_steps = [
        s
        for s in steps
        if "trivy" in s.get("run", "").lower() and "release" in s.get("run", "").lower()
    ]
    assert upload_steps, "No Trivy report release upload step found"
    cond = upload_steps[0].get("if", "")
    assert "release" in cond, (
        f"Trivy report upload step 'if:' condition '{cond}' must be gated on the release event"
    )


# ---------------------------------------------------------------------------
# Ordering: gate must precede push (signing can only happen after push)
# ---------------------------------------------------------------------------


def test_trivy_gate_precedes_push() -> None:
    """The blocking Trivy scan must appear before the multi-arch push step."""
    steps = _job_steps(_load_workflow())
    trivy_indices = [
        i
        for i, s in enumerate(steps)
        if s.get("uses", "").startswith("aquasecurity/trivy-action")
        and s.get("with", {}).get("exit-code") == "1"
    ]
    push_indices = [
        i
        for i, s in enumerate(steps)
        if s.get("uses", "").startswith("docker/build-push-action")
        and "arm64" in str(s.get("with", {}).get("platforms", ""))
    ]
    assert trivy_indices and push_indices, (
        "Could not find both blocking Trivy step and multi-arch push step"
    )
    assert max(trivy_indices) < min(push_indices), (
        "Blocking Trivy scan must appear before the multi-arch build-push step "
        "so a CVE-failing image is never pushed"
    )


def test_cosign_sign_follows_push() -> None:
    """The cosign sign step must appear after the multi-arch push step."""
    steps = _job_steps(_load_workflow())
    sign_indices = [i for i, s in enumerate(steps) if "cosign sign" in s.get("run", "")]
    push_indices = [
        i
        for i, s in enumerate(steps)
        if s.get("uses", "").startswith("docker/build-push-action")
        and "arm64" in str(s.get("with", {}).get("platforms", ""))
    ]
    assert sign_indices and push_indices, (
        "Could not find both cosign sign step and multi-arch push step"
    )
    assert min(sign_indices) > max(push_indices), (
        "cosign sign step must appear after the multi-arch build-push step "
        "— the image digest is only available after the push"
    )
