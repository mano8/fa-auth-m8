"""Layer B: real-connection concurrency races (``TEST-DB-01``, 3.5.1, 3.5.3).

Two guarantees in this file exist **only** here, by design (50 and the Phase 3A
G3 amendment): the *two-connection last-superuser race* and the
*concurrent-login-during-downgrade generation race*. Both depend on genuine lock
contention between separate connections, which is a no-op on the SQLite
surrogate — the unit suite can assert the non-concurrent rule and nothing more.

Each race runs repeatedly with a synchronization barrier so a passing result is
not one lucky interleaving.

**What a race must prove is the invariant, not one engine's mechanism.** The
three certified engines refuse a losing transaction differently: PostgreSQL
blocks on the row lock and the loser then fails the application's own
last-superuser check, while MySQL/MariaDB may abort it outright with a
serialization error (deadlock, lock-wait timeout, or MariaDB's ``1020 Record has
changed since last read``). Both are correct refusals, so the assertions below
are written against the surviving *state* — one superuser left, no session
outliving its generation — and treat "aborted by the engine" as a legitimate way
to lose.
"""

from __future__ import annotations

import threading
import uuid
from datetime import datetime, timedelta, timezone
from typing import Callable, Optional

import pytest
import sqlalchemy as sa
from sqlmodel import Session, col, select

from auth_sdk_m8.schemas.base import RoleType

from auth_user_service.db_models.outbox import RevocationOutbox
from auth_user_service.db_models.security_policy import (
    SUPERUSER_SET_POLICY_KEY,
    SecurityPolicy,
)
from auth_user_service.db_models.sessions import ClientSession, ClientSessionCreate
from auth_user_service.db_models.users import User, UserUpdate
from auth_user_service.services.client_sessions import SessionController
from auth_user_service.services.generation import GenerationController
from auth_user_service.services.role_admin import (
    LastSuperuserError,
    change_user_authorization,
    count_active_canonical_superusers,
)
from tests.integration.database._races import is_serialization_failure
from tests.integration.database._factories import (
    issue_session,
    jti,
    make_user,
    naive_utc,
)

pytestmark = pytest.mark.database_integration

#: Longer than MySQL's default ``innodb_lock_wait_timeout`` (50s): a waiter
#: that blocks on the superuser-set lock must be allowed to reach its own
#: engine-level refusal, not be declared hung by an impatient join.
_JOIN_TIMEOUT = 90.0
_REPEATS = 4


def _run_together(
    tasks: list[Callable[[], None]], *, timeout: float = _JOIN_TIMEOUT
) -> None:
    """Run *tasks* on real threads, released together by a barrier.

    An exception escaping a task is re-raised here rather than vanishing with
    its thread — a silently lost failure would make a race test pass by
    observing one participant instead of two.
    """
    barrier = threading.Barrier(len(tasks), timeout=timeout)
    failures: list[BaseException] = []

    def wrapped(task: Callable[[], None]) -> Callable[[], None]:
        def runner() -> None:
            try:
                barrier.wait()
                task()
            except BaseException as exc:  # noqa: BLE001 — surfaced to the test
                failures.append(exc)

        return runner

    threads = [threading.Thread(target=wrapped(task), daemon=True) for task in tasks]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=timeout)
        assert not thread.is_alive(), "a concurrent task never finished"
    if failures:
        raise failures[0]


def _policy_revision(engine: sa.Engine) -> int:
    with Session(engine) as session:
        policy = session.exec(
            select(SecurityPolicy).where(
                col(SecurityPolicy.policy_key) == SUPERUSER_SET_POLICY_KEY
            )
        ).one()
        return policy.revision


# ── the two-connection last-superuser race (3.5.3, G3) ────────────────────────


class TestLastSuperuserRace:
    """Concurrent set-removing mutations cannot empty the superuser set."""

    def test_two_connections_cannot_both_demote_the_last_pair(
        self, clean_database: sa.Engine, second_engine: sa.Engine
    ) -> None:
        """With exactly two superusers, two simultaneous self-demotions leave one.

        The invariant is enforced by counting the set *under* the
        ``security_policy`` row lock (3.5.3). Without real contention both
        transactions would read "2 remaining" and both would commit, emptying
        the set — which is precisely why this proof cannot live in the unit
        suite.
        """
        for attempt in range(_REPEATS):
            with Session(clean_database) as setup:
                first = make_user(setup, role=RoleType.SUPERADMIN, is_superuser=True)
                second = make_user(setup, role=RoleType.SUPERADMIN, is_superuser=True)
                first_id, second_id = first.id, second.id
            revision_before = _policy_revision(clean_database)

            outcomes: list[str] = []
            lock = threading.Lock()

            def demote(engine: sa.Engine, user_id: uuid.UUID) -> None:
                with Session(engine) as session:
                    target = session.get(User, user_id)
                    assert target is not None
                    try:
                        change_user_authorization(
                            session=session,
                            actor_id=user_id,
                            actor_role=RoleType.SUPERADMIN,
                            db_user=target,
                            user_in=UserUpdate(role=RoleType.READER),
                        )
                        result = "demoted"
                    except LastSuperuserError:
                        session.rollback()
                        result = "refused"
                    except Exception as exc:  # noqa: BLE001 — classified below
                        session.rollback()
                        if not is_serialization_failure(exc):
                            raise
                        result = "aborted"
                    with lock:
                        outcomes.append(result)

            _run_together(
                [
                    lambda: demote(clean_database, first_id),
                    lambda: demote(second_engine, second_id),
                ]
            )

            # Exactly one commits. The loser is refused by the application's own
            # invariant (PostgreSQL blocks, then fails the check) or aborted by
            # the engine (MySQL/MariaDB may serialize by refusal) — both are
            # correct ways to lose; committing twice is the only failure.
            assert outcomes.count("demoted") == 1, (
                f"attempt {attempt}: expected exactly one demotion to win, "
                f"got {outcomes}"
            )
            assert set(outcomes) <= {"demoted", "refused", "aborted"}
            with Session(clean_database) as check:
                assert count_active_canonical_superusers(check) == 1
            # The revision counter advances once per *committed* set mutation,
            # so the refused transaction leaves no trace (3.5.3).
            assert _policy_revision(clean_database) == revision_before + 1

            with Session(clean_database) as cleanup:
                for user_id in (first_id, second_id):
                    row = cleanup.get(User, user_id)
                    if row is not None:
                        cleanup.delete(row)
                cleanup.commit()


# ── concurrent login during downgrade (3.5.1, G3) ─────────────────────────────


class TestConcurrentLoginDuringDowngrade:
    """A login racing a role change can never keep the superseded authority."""

    def test_session_minted_against_a_superseded_generation_is_denied(
        self, clean_database: sa.Engine, second_engine: sa.Engine
    ) -> None:
        """The deterministic core: a stale in-flight login never gains authority.

        The login path reads the owner, then stamps the session with the
        generation it read. Here the downgrade commits in between, so one of two
        things must happen — the engine refuses the stale write outright
        (MariaDB answers ``1020 Record has changed since last read``), or the
        session lands carrying the superseded generation and the
        DB-authoritative decision denies it without any Redis involvement.
        Either way the superseded authority is not usable, which is the
        invariant; which of the two occurs is a dialect detail.
        """
        with Session(clean_database) as setup:
            user = make_user(setup, role=RoleType.WRITER)
            user_id = user.id

        minted_generation: Optional[int] = None
        # The in-flight login has already read the pre-downgrade owner.
        with Session(second_engine) as login_session:
            stale_owner = login_session.get(User, user_id)
            assert stale_owner is not None
            assert stale_owner.auth_generation == 1

            with Session(clean_database) as admin_session:
                target = admin_session.get(User, user_id)
                assert target is not None
                change_user_authorization(
                    session=admin_session,
                    actor_id=uuid.uuid4(),
                    actor_role=RoleType.SUPERADMIN,
                    db_user=target,
                    user_in=UserUpdate(role=RoleType.READER),
                )

            now = naive_utc()
            try:
                minted = SessionController.create_client_session(
                    session=login_session,
                    current_user=stale_owner,
                    session_data=ClientSessionCreate(
                        jwt_jti=jti("stale-login"),
                        refresh_token_hash="r" * 64,
                        jwt_expires_at=now + timedelta(hours=1),
                        refresh_expires_at=now + timedelta(days=7),
                    ),
                )
                minted_generation = minted.auth_generation
            except Exception as exc:  # noqa: BLE001 — classified, then asserted
                login_session.rollback()
                assert is_serialization_failure(exc), (
                    f"the stale login failed for an unexpected reason: {exc!r}"
                )

        with Session(clean_database) as check:
            if minted_generation is not None:
                assert minted_generation == 1
            decision = GenerationController.decide_jti_status(
                check, jti("stale-login"), user_id
            )
            assert decision.active is False, (
                "a session stamped with a superseded generation must be denied "
                "from database state alone (3.5.1)"
            )

    def test_repeated_race_never_yields_a_live_stale_session(
        self, clean_database: sa.Engine, second_engine: sa.Engine
    ) -> None:
        """Under real contention every surviving session is current.

        Three outcomes are legitimate — the login lands before the downgrade
        (and is revoked with every other session), lands after it (and carries
        the new role), or is aborted by the engine as a serialization failure.
        What must never happen is a *surviving* session whose stamped generation
        is behind its owner's.
        """
        for attempt in range(_REPEATS):
            with Session(clean_database) as setup:
                user = make_user(setup, role=RoleType.WRITER)
                user_id = user.id
            race_jti = jti(f"race-{attempt}")

            def downgrade() -> None:
                with Session(clean_database) as session:
                    target = session.get(User, user_id)
                    assert target is not None
                    try:
                        change_user_authorization(
                            session=session,
                            actor_id=uuid.uuid4(),
                            actor_role=RoleType.SUPERADMIN,
                            db_user=target,
                            user_in=UserUpdate(role=RoleType.READER),
                        )
                    except Exception as exc:  # noqa: BLE001 — classified below
                        session.rollback()
                        if not is_serialization_failure(exc):
                            raise
                        # A losing downgrade is retried by its caller, exactly
                        # as an operator would; the invariant is about the
                        # committed state, so drive it to completion here.
                        with Session(clean_database) as retry:
                            again = retry.get(User, user_id)
                            assert again is not None
                            change_user_authorization(
                                session=retry,
                                actor_id=uuid.uuid4(),
                                actor_role=RoleType.SUPERADMIN,
                                db_user=again,
                                user_in=UserUpdate(role=RoleType.READER),
                            )

            def login() -> None:
                with Session(second_engine) as session:
                    owner = session.get(User, user_id)
                    assert owner is not None
                    now = naive_utc()
                    try:
                        SessionController.create_client_session(
                            session=session,
                            current_user=owner,
                            session_data=ClientSessionCreate(
                                jwt_jti=race_jti,
                                refresh_token_hash="r" * 64,
                                jwt_expires_at=now + timedelta(hours=1),
                                refresh_expires_at=now + timedelta(days=7),
                            ),
                        )
                    except Exception as exc:  # noqa: BLE001 — classified below
                        session.rollback()
                        if not is_serialization_failure(exc):
                            raise

            _run_together([downgrade, login])

            with Session(clean_database) as check:
                owner = check.get(User, user_id)
                assert owner is not None
                assert owner.role is RoleType.READER
                surviving = check.exec(
                    select(ClientSession).where(col(ClientSession.jwt_jti) == race_jti)
                ).first()
                if surviving is not None:
                    decision = GenerationController.decide_jti_status(
                        check, race_jti, user_id
                    )
                    # A surviving row is only usable if its stamped generation
                    # is the owner's current one. A row minted against the
                    # superseded generation may well survive the delete (it did
                    # not exist when the delete ran) — the generation, not the
                    # row's existence, is what revokes it.
                    if surviving.auth_generation == owner.auth_generation:
                        assert decision.active is True
                    else:
                        assert decision.active is False, (
                            f"attempt {attempt}: a session stamped with a "
                            "superseded generation was still accepted"
                        )

            with Session(clean_database) as cleanup:
                row = cleanup.get(User, user_id)
                if row is not None:
                    cleanup.delete(row)
                cleanup.commit()


# ── concurrent role changes on distinct subjects ──────────────────────────────


class TestConcurrentRoleChanges:
    def test_both_commit_and_the_revision_counts_each_one(
        self, clean_database: sa.Engine, second_engine: sa.Engine
    ) -> None:
        """Serialization is not starvation: unrelated changes both land.

        The lock exists to order set mutations, not to reject them, so two
        demotions of ordinary users must both end up committed and the monotonic
        revision must advance exactly twice. One attempt may be aborted by the
        engine as a serialization failure — the ordinary, retryable outcome an
        operator's client already handles — so each task retries once before its
        result is judged.
        """
        with Session(clean_database) as setup:
            first_id = make_user(setup, role=RoleType.WRITER).id
            second_id = make_user(setup, role=RoleType.WRITER).id
        revision_before = _policy_revision(clean_database)

        def demote(engine: sa.Engine, user_id: uuid.UUID) -> None:
            for remaining in (1, 0):
                with Session(engine) as session:
                    target = session.get(User, user_id)
                    assert target is not None
                    try:
                        change_user_authorization(
                            session=session,
                            actor_id=uuid.uuid4(),
                            actor_role=RoleType.SUPERADMIN,
                            db_user=target,
                            user_in=UserUpdate(role=RoleType.READER),
                        )
                        return
                    except Exception as exc:  # noqa: BLE001 — classified below
                        session.rollback()
                        if not remaining or not is_serialization_failure(exc):
                            raise

        _run_together(
            [
                lambda: demote(clean_database, first_id),
                lambda: demote(second_engine, second_id),
            ]
        )

        with Session(clean_database) as check:
            for user_id in (first_id, second_id):
                user = check.get(User, user_id)
                assert user is not None
                assert user.role is RoleType.READER
                assert user.auth_generation == 2
        assert _policy_revision(clean_database) == revision_before + 2


# ── rollback after partial failure ────────────────────────────────────────────


class TestTransactionRollback:
    def test_partial_failure_leaves_no_authorization_state_behind(
        self, clean_database: sa.Engine, second_engine: sa.Engine
    ) -> None:
        """A transaction that fails mid-way changes nothing another connection sees.

        Role, generation, sessions, and the durable outbox rows all belong to
        one unit of work (3.5.2). This drives the real mutations, then aborts,
        and verifies the outcome from a **separate connection** — an in-process
        rollback assertion on the same session could pass on stale identity-map
        state alone.
        """
        with Session(clean_database) as setup:
            user = make_user(setup, role=RoleType.WRITER)
            user_id = user.id
            issue_session(setup, user, jti=jti("rollback"))

        with Session(clean_database) as session:
            target = session.get(User, user_id)
            assert target is not None
            target.role = RoleType.READER
            target.auth_generation = 2
            session.exec(  # type: ignore[call-overload]
                sa.delete(ClientSession).where(col(ClientSession.user_id) == user_id)
            )
            session.add(
                RevocationOutbox(
                    user_id=user_id,
                    auth_generation=2,
                    effect_type="blacklist",
                    target_digest="rollback-digest",
                    payload={
                        "jti": jti("rollback"),
                        "expires_at": datetime.now(timezone.utc).isoformat(),
                    },
                    status="pending",
                )
            )
            session.flush()
            session.rollback()

        with Session(second_engine) as check:
            reloaded = check.get(User, user_id)
            assert reloaded is not None
            assert reloaded.role is RoleType.WRITER
            assert reloaded.auth_generation == 1
            surviving: Optional[ClientSession] = check.exec(
                select(ClientSession).where(
                    col(ClientSession.jwt_jti) == jti("rollback")
                )
            ).first()
            assert surviving is not None, "the rollback lost a committed session"
            assert check.exec(select(RevocationOutbox)).all() == []
