"""Every platform the publish workflow pushes is Trivy-gated before the push.

The multi-arch push ships `linux/amd64` and `linux/arm64`, but the gate used to
scan an amd64-only build, so the arm64 image reached the registry unscanned.
This asserts, for each platform in the push step, a single-platform `load: true`
build and a blocking Trivy scan of that build, both ahead of the push. The
workflow is read as text so the test needs no YAML parser, Docker or network.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
DOCKER_PUBLISH_YAML = REPO_ROOT / ".github" / "workflows" / "docker-publish.yaml"

_STEP_START = re.compile(r"^\s*- (?:name|uses): ", re.MULTILINE)


def _steps() -> list[str]:
    text = DOCKER_PUBLISH_YAML.read_text(encoding="utf-8")
    starts = [m.start() for m in _STEP_START.finditer(text)]
    return [text[a:b] for a, b in zip(starts, starts[1:] + [len(text)])]


def _field(step: str, key: str) -> str | None:
    match = re.search(rf"^\s*{key}:\s*(.+?)\s*$", step, re.MULTILINE)
    return match.group(1).strip("\"'") if match else None


def test_every_pushed_platform_is_scanned_before_the_push() -> None:
    steps = _steps()
    push_at = next(
        i
        for i, step in enumerate(steps)
        if "docker/build-push-action" in step and _field(step, "push") != "false"
    )
    pushed = [p.strip() for p in (_field(steps[push_at], "platforms") or "").split(",")]
    assert len(pushed) > 1, "expected a multi-arch push"

    before = steps[:push_at]
    for platform in pushed:
        build = next(
            (
                step
                for step in before
                if "docker/build-push-action" in step
                and _field(step, "platforms") == platform
                and _field(step, "load") == "true"
            ),
            None,
        )
        assert build is not None, f"{platform} is pushed but never built for a scan"
        tag = _field(build, "tags")
        assert any(
            "aquasecurity/trivy-action" in step
            and _field(step, "image-ref") == tag
            and _field(step, "exit-code") == "1"
            for step in before
        ), f"{platform} is built as {tag} but no blocking Trivy scan reads it"
