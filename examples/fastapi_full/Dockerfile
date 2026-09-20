# ---------- BUILD STAGE ----------
FROM python:3.14-slim@sha256:caaf356f40667c496d405780745b9ac25771c189a51dfcc42430d531ea09f8a2 AS builder

WORKDIR /install

ARG ENVIRONMENT=production
ENV PIP_ROOT_USER_ACTION=ignore

COPY ./fastapi_full/requirements_base.txt .
COPY ./fastapi_full/requirements_dev.txt .
COPY ./fastapi_full/requirements_prod.txt .

RUN pip install --upgrade "pip==26.1.1" && \
    pip install --prefix=/install --no-cache-dir -r requirements_base.txt && \
    if [ "$ENVIRONMENT" = "development" ]; then \
        pip install --prefix=/install --no-cache-dir -r requirements_dev.txt ; \
    else \
        pip install --prefix=/install --no-cache-dir -r requirements_prod.txt ; \
    fi


# ---------- RUNTIME STAGE ----------
FROM python:3.14-slim@sha256:caaf356f40667c496d405780745b9ac25771c189a51dfcc42430d531ea09f8a2

ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV PATH="/home/appuser/.local/bin:$PATH"
ENV PYTHONPATH=/opt/fastapi_full

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
COPY --chown=appuser:appuser ./fastapi_full ./fastapi_full

USER appuser

EXPOSE 8000

CMD ["./fastapi_full/scripts/docker_start.sh"]
