# ---------- BUILD STAGE ----------
FROM python:3.14-slim@sha256:caaf356f40667c496d405780745b9ac25771c189a51dfcc42430d531ea09f8a2 AS builder

WORKDIR /install

ARG ENVIRONMENT=production
ENV PIP_ROOT_USER_ACTION=ignore

COPY auth_user_service/requirements_base.txt .
COPY auth_user_service/requirements_dev.txt .
COPY auth_user_service/requirements_prod.txt .
COPY auth_user_service/requirements_prod.lock .

# Release images install from a hash-locked, fully pinned dependency set so a
# rebuild of the same source cannot silently resolve a different graph
# (finding 11.8). `--require-hashes` is enforced for every non-development
# build. Regenerate the lock with:
#   pip-compile --generate-hashes --no-emit-index-url \
#     --output-file=requirements_prod.lock requirements_prod.txt
RUN pip install --upgrade "pip==26.1.1" && \
    if [ "$ENVIRONMENT" = "development" ]; then \
        pip install --prefix=/install --no-cache-dir -r requirements_base.txt && \
        pip install --prefix=/install --no-cache-dir -r requirements_dev.txt ; \
    else \
        pip install --prefix=/install --no-cache-dir \
            --require-hashes -r requirements_prod.lock ; \
    fi


# ---------- RUNTIME STAGE ----------
FROM python:3.14-slim@sha256:caaf356f40667c496d405780745b9ac25771c189a51dfcc42430d531ea09f8a2

ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV PATH="/home/appuser/.local/bin:$PATH"
ENV PYTHONPATH=/opt/auth_user_service

# Debian patch layer — the one fleet form; owner: the workspace's
# `.workspace/context/debian-patch-layer.md`. Every Debian package self-heals
# on each build through `apt-get upgrade -y`; nothing is exact-pinned and
# nothing is installed that the base does not already ship. The base digest
# above moves in lock-step with the other service images, never alone. If a
# package must ever lead the pinned base, the recorded form is an unpinned
# install plus a `dpkg --compare-versions … ge <floor>` assertion in this same
# RUN — never an exact `=` pin, which freezes the image on the next advisory.
RUN apt-get update \
    && apt-get upgrade -y \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd --gid 1000 appuser && \
    useradd --uid 1000 --gid appuser --create-home appuser

WORKDIR /opt

COPY --from=builder /install /usr/local
COPY --chown=appuser:appuser ./auth_user_service ./auth_user_service

RUN find /opt/auth_user_service/scripts -name "*.sh" -exec sed -i 's/\r$//' {} + && \
    chmod +x /opt/auth_user_service/scripts/*.sh

# Drop pip from the runtime image, as the other four service images already
# do. Nothing here installs anything at run time: `docker_start.sh` runs
# alembic and uvicorn, and the release set is installed hash-locked in the
# builder. pip is dead weight - and not inert dead weight: from pip 26.2.1
# (the pip the base digest above ships) it carries an SBOM of its vendored
# dependency tree (pip/_vendor/bom.cdx.json) that Trivy reads as installed
# packages, surfacing GHSA-6v7p-g79w-8964 (msgpack 1.1.2) and CVE-2025-47273
# (setuptools 70.3.0) - both pip's vendored copies, neither in
# requirements_prod.lock nor in `pip list`. Removing pip deletes the code
# instead of ignoring the report, which is why this is not a .trivyignore
# entry. setuptools and wheel are not shipped by this base; `pip list` in
# the digest above reads pip alone.
RUN python -m pip uninstall -y pip \
    && rm -rf "$(python -c 'import sysconfig; print(sysconfig.get_paths()["purelib"])')/pip" \
    && rm -f /usr/local/bin/pip /usr/local/bin/pip3 /usr/local/bin/pip3.*

USER appuser

EXPOSE 8000

CMD ["./auth_user_service/scripts/docker_start.sh"]
