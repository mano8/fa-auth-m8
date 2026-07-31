"""Certified engine registry and ephemeral container provisioning (``TEST-DB-01``, 4.6).

The Layer B matrix runs against **ephemeral real database containers**, never a
permanently shared database and never the SQLite unit-test surrogate. The three
certified dialects and their exact version pins are owned by the supported
database contract (4.6) and mirrored here:

===========  ========================  ===================================
Matrix key   Pinned image              Maintained example whose chain
                                       certifies the dialect
===========  ========================  ===================================
postgresql   ``postgres:18.4-alpine``  ``examples/docker_compose/postgres_m8``
mysql        ``mysql:8.4.10``          ``examples/docker_compose/rs256_m8``
mariadb      ``mariadb:12.3.2-ubi``    ``examples/docker_compose/quickstart_m8``
===========  ========================  ===================================

MySQL and MariaDB are **separate certified dialects** (4.6): they share the
``mysql+pymysql`` driver family, so both run the same MySQL-flavoured migration
chain, but passing on one is never evidence for the other — which is exactly why
each has its own matrix entry and its own pinned image.

Two provisioning modes, selected by ``FA_AUTH_IT_MODE``:

``container`` (default)
    Start a disposable container from the pinned image on a free host port,
    wait for it to accept connections, and remove it at session teardown. This
    is what a developer runs locally; it needs a working Docker daemon.
``external``
    Connect to an already-running instance described by the ``FA_AUTH_IT_*``
    environment variables — the CI service-container shape, where the runner
    provisions the engine and this suite only consumes it.

Either way the target must be **disposable**: the migration tests drop and
recreate the whole schema.
"""

from __future__ import annotations

import os
import socket
import subprocess  # nosec B404 — the Docker CLI is invoked with a fixed argv list
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import sqlalchemy as sa

REPO_ROOT = Path(__file__).resolve().parents[3]

#: Matrix keys, in the order the CI matrix declares them.
DIALECTS = ("postgresql", "mysql", "mariadb")

# Disposable credentials for the ephemeral target. The password satisfies the
# SDK's password-strength validator (8+ chars, upper/lower/digit/special), which
# ``CommonSettings.SQLALCHEMY_DATABASE_URI`` enforces on every build.
IT_DATABASE = "auth_it_db"
IT_USER = "auth_it_user"
IT_PASSWORD = "ItTestDb1!secure"  # nosec B105 — throwaway container credential


@dataclass(frozen=True)
class EngineSpec:
    """One certified engine of the 4.6 matrix."""

    #: Matrix key (``postgresql`` | ``mysql`` | ``mariadb``).
    key: str
    #: Exact pinned image (4.6) — never a floating tag.
    image: str
    #: ``SELECTED_DB`` declaration naming this engine (4.6 dialect declaration).
    selected_db: str
    #: SQLAlchemy dialect name reported by the connected engine.
    dialect: str
    #: Port the engine listens on inside the container.
    container_port: int
    #: Maintained compose example whose Alembic chain certifies this dialect.
    example_stack: str
    #: Container environment that provisions the disposable database/user.
    container_env: tuple[tuple[str, str], ...]
    #: Extra image arguments (health/startup tuning only — never schema policy).
    command: tuple[str, ...] = ()

    @property
    def shared_migrations(self) -> Path:
        """Root of the certifying stack's shared Alembic chains."""
        return (
            REPO_ROOT
            / "examples"
            / "docker_compose"
            / self.example_stack
            / "shared_migrations"
        )

    @property
    def version_locations(self) -> Path:
        """Alembic ``version_locations`` for this dialect's certified chain."""
        return self.shared_migrations / "auth_user" / "versions"

    @property
    def app_version_locations(self) -> Path:
        """``version_locations`` for the same stack's bundled-example chain.

        Every maintained compose stack ships the consumer example's ``m8_app``
        chain next to the issuer's ``auth_user`` chain, so the dialect selection
        that picks one picks the other — the example chain needs no second
        selector, only a second version table.
        """
        return self.shared_migrations / "m8_app" / "versions"


ENGINE_SPECS: dict[str, EngineSpec] = {
    "postgresql": EngineSpec(
        key="postgresql",
        image="postgres:18.4-alpine",
        selected_db="Postgres",
        dialect="postgresql",
        container_port=5432,
        example_stack="postgres_m8",
        container_env=(
            ("POSTGRES_DB", IT_DATABASE),
            ("POSTGRES_USER", IT_USER),
            ("POSTGRES_PASSWORD", IT_PASSWORD),
        ),
    ),
    "mysql": EngineSpec(
        key="mysql",
        image="mysql:8.4.10",
        selected_db="Mysql",
        dialect="mysql",
        container_port=3306,
        example_stack="rs256_m8",
        container_env=(
            ("MYSQL_DATABASE", IT_DATABASE),
            ("MYSQL_USER", IT_USER),
            ("MYSQL_PASSWORD", IT_PASSWORD),
            ("MYSQL_ROOT_PASSWORD", IT_PASSWORD),
        ),
    ),
    "mariadb": EngineSpec(
        key="mariadb",
        image="mariadb:12.3.2-ubi",
        selected_db="Mariadb",
        dialect="mysql",
        container_port=3306,
        example_stack="quickstart_m8",
        container_env=(
            ("MARIADB_DATABASE", IT_DATABASE),
            ("MARIADB_USER", IT_USER),
            ("MARIADB_PASSWORD", IT_PASSWORD),
            ("MARIADB_ROOT_PASSWORD", IT_PASSWORD),
        ),
    ),
}


@dataclass(frozen=True)
class Endpoint:
    """A reachable, disposable database instance."""

    host: str
    port: int
    database: str
    user: str
    password: str

    def uri(self, spec: EngineSpec) -> sa.engine.URL:
        """Build the connection URL for the same driver ``CommonSettings`` picks.

        Constructed through ``URL.create`` rather than string interpolation so a
        password containing URI-reserved characters is escaped by SQLAlchemy
        itself — the same class of bug the settings builder avoids with
        ``quote_plus``.
        """
        driver = (
            "postgresql+psycopg2" if spec.selected_db == "Postgres" else "mysql+pymysql"
        )
        return sa.engine.URL.create(
            driver,
            username=self.user,
            password=self.password,
            host=self.host,
            port=self.port,
            database=self.database,
        )


class DockerUnavailable(RuntimeError):
    """Raised when container mode is requested but no usable Docker daemon exists."""


class TargetNotProvisioned(RuntimeError):
    """The target cannot accept the migrations a real deployment must apply."""


def apply_deployment_prerequisites(spec: EngineSpec, endpoint: Endpoint) -> None:
    """Grant the target the privileges a real deployment must already hold.

    **MySQL only, and it is a genuine deployment prerequisite, not a test hack.**
    MySQL 8 enables binary logging by default, and a user without ``SUPER``
    cannot then create a trigger unless ``log_bin_trust_function_creators`` is
    on — error 1419. The privileged-action audit table's write-once guard *is* a
    trigger, so `alembic upgrade head` fails for an ordinary application user on
    a stock MySQL 8 server. Replicating the prerequisite here is what lets the
    matrix certify the migration the way a correctly provisioned deployment runs
    it; the requirement itself is documented in the issuer runbook.

    MariaDB ships with binary logging off, so the statement is a harmless no-op
    there and its failure is never fatal.
    """
    if spec.dialect != "mysql":
        return
    root_user = os.environ.get("FA_AUTH_IT_ROOT_USER", "root")
    root_password = os.environ.get("FA_AUTH_IT_ROOT_PASSWORD", IT_PASSWORD)
    admin = Endpoint(
        host=endpoint.host,
        port=endpoint.port,
        database=endpoint.database,
        user=root_user,
        password=root_password,
    )
    engine = sa.create_engine(
        admin.uri(spec),
        future=True,
        connect_args={"connect_timeout": CONNECT_TIMEOUT_SECONDS},
    )
    try:
        with engine.begin() as conn:
            conn.execute(sa.text("SET GLOBAL log_bin_trust_function_creators = 1"))
    except Exception as exc:  # noqa: BLE001 — reported with the remedy
        if spec.key == "mariadb":
            return
        raise TargetNotProvisioned(
            "MySQL requires log_bin_trust_function_creators=ON (or SUPER) before "
            "the audit-table guard trigger can be created by a non-SUPER user "
            f"while binary logging is enabled: {exc}"
        ) from exc
    finally:
        engine.dispose()


def _docker(*args: str, check: bool = True, timeout: int = 120) -> str:
    """Run one Docker CLI command with a fixed argument vector."""
    result = subprocess.run(  # nosec B603 — fixed argv, no shell, no user input
        ["docker", *args],
        capture_output=True,
        text=True,
        check=False,
        timeout=timeout,
    )
    if check and result.returncode != 0:
        raise DockerUnavailable(
            f"docker {' '.join(args)} failed ({result.returncode}): "
            f"{result.stderr.strip()[:400]}"
        )
    return result.stdout.strip()


def docker_is_available() -> bool:
    """Whether a Docker daemon is reachable (Layer B is skipped when it is not)."""
    try:
        _docker("info", "--format", "{{.ServerVersion}}", timeout=30)
    except (DockerUnavailable, OSError, subprocess.SubprocessError):
        return False
    return True


def _free_port() -> int:
    """Reserve an ephemeral host port for the container's published port."""
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


#: Both certified drivers accept ``connect_timeout`` (seconds). Bounding the
#: probe matters: a candidate that is merely *unreachable* (a blackholed route,
#: a publish that belongs to another host) would otherwise hang the connect
#: syscall indefinitely and turn "not this endpoint" into "the suite never
#: starts".
CONNECT_TIMEOUT_SECONDS = 5


def _accepts_connection(spec: EngineSpec, endpoint: Endpoint) -> bool:
    """Whether the app credentials can open a real session on *endpoint*.

    Readiness is proven by the same driver the service uses, not by a port
    check: MySQL/MariaDB accept TCP well before the seeded user exists.
    """
    engine = sa.create_engine(
        endpoint.uri(spec),
        future=True,
        connect_args={"connect_timeout": CONNECT_TIMEOUT_SECONDS},
    )
    try:
        with engine.connect() as conn:
            conn.execute(sa.text("SELECT 1"))
        return True
    except Exception:  # noqa: BLE001 — any driver error means "not yet"
        return False
    finally:
        engine.dispose()


def wait_until_ready(
    spec: EngineSpec, endpoint: Endpoint, *, timeout: float = 180.0
) -> None:
    """Block until *endpoint* is usable, or fail with a clear diagnosis."""
    wait_until_ready_any(spec, [endpoint], timeout=timeout)


def wait_until_ready_any(
    spec: EngineSpec, candidates: list[Endpoint], *, timeout: float = 180.0
) -> Endpoint:
    """Return the first candidate endpoint that becomes usable.

    A started container is reachable one way on an ordinary Docker host (the
    published ``127.0.0.1`` port) and another way when the test process is
    itself containerized against a shared daemon — Docker-out-of-Docker, the
    usual dev-container and CI-runner shape — where the publish lands on the
    *host's* loopback and the container is reached on its bridge address
    instead. Probing both keeps one suite honest in both topologies rather
    than silently skipping in one of them.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        for endpoint in candidates:
            if _accepts_connection(spec, endpoint):
                return endpoint
        time.sleep(1.0)
    described = ", ".join(f"{c.host}:{c.port}" for c in candidates)
    raise DockerUnavailable(
        f"{spec.key} target ({described}) never became ready within {timeout:.0f}s"
    )


def external_endpoint(spec: EngineSpec) -> Endpoint:
    """Describe an externally provisioned instance (CI service container)."""
    return Endpoint(
        host=os.environ.get("FA_AUTH_IT_HOST", "127.0.0.1"),
        port=int(os.environ.get("FA_AUTH_IT_PORT", spec.container_port)),
        database=os.environ.get("FA_AUTH_IT_DATABASE", IT_DATABASE),
        user=os.environ.get("FA_AUTH_IT_USER", IT_USER),
        password=os.environ.get("FA_AUTH_IT_PASSWORD", IT_PASSWORD),
    )


class EphemeralDatabase:
    """A disposable container running one pinned engine of the matrix."""

    def __init__(self, spec: EngineSpec) -> None:
        self.spec = spec
        self.container_id: Optional[str] = None
        self.name = f"fa-auth-it-{spec.key}-{uuid.uuid4().hex[:8]}"

    def start(self) -> Endpoint:
        """Run the container and return its reachable endpoint."""
        port = _free_port()
        args = [
            "run",
            "--detach",
            "--name",
            self.name,
            "--publish",
            f"127.0.0.1:{port}:{self.spec.container_port}",
            # Ephemeral by construction: the data directory is a tmpfs-backed
            # anonymous volume that dies with the container.
            "--rm",
        ]
        for key, value in self.spec.container_env:
            args += ["--env", f"{key}={value}"]
        args.append(self.spec.image)
        args += list(self.spec.command)
        self.container_id = _docker(*args)
        candidates = [
            Endpoint(
                host="127.0.0.1",
                port=port,
                database=IT_DATABASE,
                user=IT_USER,
                password=IT_PASSWORD,
            )
        ]
        bridge_address = self.bridge_address()
        if bridge_address:
            candidates.append(
                Endpoint(
                    host=bridge_address,
                    port=self.spec.container_port,
                    database=IT_DATABASE,
                    user=IT_USER,
                    password=IT_PASSWORD,
                )
            )
        try:
            return wait_until_ready_any(self.spec, candidates)
        except Exception:
            self.stop()
            raise

    def bridge_address(self) -> Optional[str]:
        """The container's own network address, used when the publish is not ours."""
        address = _docker(
            "inspect",
            "--format",
            "{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}",
            self.name,
            check=False,
            timeout=30,
        )
        first = address.split()
        return first[0] if first else None

    def stop(self) -> None:
        """Remove the container; never leaves state behind for the next run."""
        if self.container_id is None:
            return
        _docker("rm", "--force", "--volumes", self.name, check=False, timeout=60)
        self.container_id = None
