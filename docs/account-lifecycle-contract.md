# Account-lifecycle contract

Status: **frozen** (C1, 2026-09-27). Capability document version `1.0`.

This document is the authority for the optional account-lifecycle features of
`fa-auth-m8`: public signup, email verification, forgotten-password recovery,
and confirmed email change. It fixes what later implementation must follow;
changing a frozen rule needs an explicit amendment here, in the same change as
the code.

Nothing in this contract is implemented as a route yet. The code that already
exists is the part a later item builds on:

| Piece | Code |
| --- | --- |
| Challenge-token mint, parse, digest, TTLs | `auth_user_service/core/challenge_tokens.py` |
| Capability document, error codes, action response | `auth_user_service/schemas/account_lifecycle.py` |
| Cross-family rejection proofs | `tests/security/test_challenge_token_family.py` |

## 1. Decisions

| # | Decision | Rule |
| --- | --- | --- |
| `D-c` | Authenticated password change | Revokes **every** session of the account, the caller's included; the client signs in again. Implemented in `2.2.4` (`services/password.py`). |
| `D-e` | Contract versioning | The issuer `CONTRACT_VERSION` stays `"2.0"`; the capability document carries its own `capabilities_version`. |
| `D-f` | Verification setting | Tri-state `EMAIL_VERIFICATION_MODE=off\|optional\|required`. |
| `D-g` | Google/password collision | No implicit linking. Google binds on `(provider=google, oauth_user_id=sub)`; an email held by another account is refused generically. Implemented in `2.2.4`. |
| `D-h` | Mail delivery | Best-effort send after commit and after the response, no durable queue. Every mail is user-retriable ("resend"), and the raw token never touches disk. |
| `D-j` | Deletion and Google identities | Every deletion runs the one tombstone and revocation transaction; only an admin deletion blocks the Google identity. Implemented in `2.2.4`. |

## 2. Capability document

`GET {API_PREFIX}/account/capabilities` — unauthenticated, `200`,
`Cache-Control: public, max-age=60`. The type is `AccountCapabilities`.

```json
{
  "capabilities_version": "1.0",
  "login_providers": ["password", "google"],
  "public_signup": true,
  "email_verification": "optional",
  "password_reset": true,
  "email_change_confirmation": true,
  "unverified_signup_expiry_days": 7,
  "paths": {
    "password_login": "/login/access-token",
    "google_login": "/google-api/login-url/",
    "signup": "/account/register",
    "verify_email_request": "/account/verify-email/request",
    "verify_email_confirm": "/account/verify-email/confirm",
    "password_reset_request": "/account/password-reset/request",
    "password_reset_confirm": "/account/password-reset/confirm",
    "email_change_confirm": "/account/email-change/confirm"
  }
}
```

- `login_providers` lists the enabled sign-in methods, as `AuthProviderType`
  values (`password`, `google`).
- `email_change_confirmation` is `true` exactly when mail is enabled: an email
  change then waits for confirmation from the new mailbox.
- `unverified_signup_expiry_days` is set exactly when public signup runs with
  verification on; otherwise it is `null`.
- Every path is relative to `API_PREFIX`, made of lowercase slug segments
  only. It cannot carry a scheme, host, `//`, `..`, query, or fragment.
- A path is non-`null` **if and only if** its feature is enabled. The model
  rejects any other combination, so the document cannot advertise a disabled
  route or hide an enabled one.
- The document never carries an SMTP host, user, or port, a domain allowlist,
  an internal URL, or key material. Unknown fields are rejected.
- The document is advisory for the UI. Every route enforces its own flag,
  whatever the client believes.

**Versioning.** A new optional field is a minor bump of
`capabilities_version` (`1.1`); removing, renaming, or retyping a field is a
major bump (`2.0`). Clients ignore fields they do not know.

**Legacy profile.** A client that gets `404` from the capability path is
talking to a release without it and uses the legacy profile: password login
only, admin-only user creation, no mail. A deployment with every new flag off
serves exactly that profile: `login_providers: ["password"]` (plus `google`
when configured), every other feature off, and only the login paths set.

## 3. Routes

All routes are relative to `API_PREFIX`. Every request body is a typed model
with `extra="forbid"`; emails are normalized (trimmed, lower-cased) before rate
limiting and lookup.

| Route | Auth | Body | Success | Feature |
| --- | --- | --- | --- | --- |
| `GET /account/capabilities` | none | — | `200` capability document | always |
| `POST /account/register` | none | `email`, `password`, `full_name` | `202 {"status":"accepted"}` | public signup |
| `POST /account/verify-email/request` | none | `email` | `202 {"status":"accepted"}` | verification ≠ `off` |
| `POST /account/verify-email/confirm` | none | `token` | `200 {"status":"completed"}` | verification ≠ `off` |
| `POST /account/password-reset/request` | none | `email` | `202 {"status":"accepted"}` | password reset |
| `POST /account/password-reset/confirm` | none | `token`, `new_password` | `200 {"status":"completed"}` | password reset |
| `POST /account/email-change/confirm` | none | `token` | `200 {"status":"completed"}` | mail enabled |
| `PATCH /profile/update/me/` (existing) | bearer | adds nothing | mail off: `200` user, applied at once; mail on: `202 {"status":"accepted"}`, held as pending | always |
| `POST /users/{user_id}/email-verification/send` | superuser | — | `202 {"status":"accepted"}` | verification ≠ `off` |
| `POST /users/{user_id}/email-verification/mark-verified` | superuser | — | `200` user, audited | always |

The existing `/users/new_user/` and `/users/signup/` stay superuser-only and
unchanged. No `GET` route consumes a challenge.

## 4. Challenge tokens

Challenge tokens are their own family, separate from every M8 JWT.

| Property | Rule |
| --- | --- |
| Format | Purpose prefix + 43 characters of unpadded base64url over 32 random bytes (256 bits). No `.`, so no JWT decoder accepts one. |
| Prefix | `m8vfy_` verification, `m8rst_` reset, `m8eml_` email change. The prefix routes a token; it is not a security control. |
| Storage | Only the SHA-256 hex digest of the whole token, prefix included. The raw token exists in the request's memory and in the sent mail, never in a DB row, log, metric, trace, or queue. |
| Binding | User id, the email address at issue time (for email change, also the new address), and the account's `auth_generation` at issue time. |
| Use | Single use. Consumption is one conditional update, so concurrent attempts produce exactly one success on every supported database. |
| Supersession | One live challenge per user and purpose: issuing a new one invalidates the older one. |
| Delivery | Emailed link to `PUBLIC_UI_URL` + UI path, token in the URL **fragment**: `#token=<token>`. The UI page sends `Referrer-Policy: no-referrer`, clears the fragment before rendering, and submits the token only by an explicit user `POST`. |
| Cross-acceptance | The challenge parser accepts only the exact format of the route's purpose. No JWT validator accepts a challenge token, and no challenge route accepts a JWT or API key. |

| Purpose | Prefix | Default TTL | Allowed TTL | Consume route | UI page |
| --- | --- | --- | --- | --- | --- |
| Email verification | `m8vfy_` | 24 h | 15 min – 24 h | `POST /account/verify-email/confirm` | `/auth/verify-email` |
| Password reset | `m8rst_` | 30 min | 5 – 30 min | `POST /account/password-reset/confirm` | `/auth/reset-password` |
| Email change | `m8eml_` | 1 h | 10 min – 1 h | `POST /account/email-change/confirm` | `/auth/confirm-email-change` |

A challenge is rejected, with the one `challenge_invalid` response, when any of
these holds at consumption:

- the value does not parse for the route's purpose;
- no stored digest matches, or it was already used or superseded;
- it has expired;
- the account is gone or inactive;
- the account's email differs from the one bound at issue;
- the account's `auth_generation` moved since issue. Any password change,
  reset, admin password set, applied email change, role change, session
  remediation, or deletion bumps it, so all of them invalidate every
  outstanding challenge of the account.

Consuming a verification challenge does not bump the generation. Consuming a
reset or an email-change challenge does, through the revoking mutation below,
so the account's other challenges die with it.

## 5. Behavior rules

1. **Mail is off by default.** `optional` or `required` verification, reset,
   and email-change confirmation need complete mail configuration, an HTTPS
   `PUBLIC_UI_URL`, and a non-empty `ALLOWED_HOSTS`. Public signup without mail
   runs only with `EMAIL_VERIFICATION_MODE=off`.
2. **Non-disclosure.** Register, verification request, and reset request
   answer the same status, body, and headers for an existing, non-existing,
   Google-only, or disabled account, and do equal request-path work. Mail is
   sent after the response. With verification `off`, a duplicate signup can
   still be discovered by then failing to log in; that equals the existing
   login oracle and is documented, not claimed closed.
3. **Per-recipient budget is silent.** When a recipient's cooldown or daily cap
   is exhausted, the request still answers `202` and no mail is sent. Only the
   per-IP and per-account limits answer `429`.
4. **Password mutation revokes.** Authenticated change and reset both bump
   `auth_generation`, revoke every M8 session (`D-c`), and so invalidate every
   outstanding challenge. A reset never signs the user in. A completed reset
   whose token went to the current address sets `email_verified=true`.
5. **Email change.** Google accounts cannot change their email (`403`);
   password accounts must send `current_password`. With mail disabled the
   change applies at once and clears `email_verified`. With mail enabled the
   new address is held as pending and applied only by confirmation from the new
   mailbox; the old address is notified. When the new address belongs to
   another account, the response is the same `202`, and the new mailbox gets an
   "address already in use" notice instead of a challenge.
6. **Required verification.** With `required`, a password login with the
   correct password for an unverified account answers `403 email_unverified`
   and triggers a throttled verification resend. `optional` never blocks.
   Google accounts are verified by Google and are never blocked.
7. **Unverified public signups expire.** With public signup and verification
   on, an account created by public signup that is still unverified after
   `unverified_signup_expiry_days` is deleted through the normal deletion
   transaction (tombstone, revocation, no Google block). Admin-created accounts
   never expire.
8. **Nothing trusts the request host.** Mail links and the Google callback come
   from configuration only.
9. **Existing accounts are not blanket-verified.** Every existing password
   account, the first superuser included, starts unverified. The rollout is
   `off → optional → required`, with an operator report of unverified active
   and superuser accounts before `required`.

## 6. Error shapes

Every error uses the existing envelope `{"detail": <value>}`. The new routes
use these `detail` values (`AccountErrorCode`):

| Status | `detail` | When |
| --- | --- | --- |
| `404` | `feature_unavailable` | The route's feature is disabled. No work is done. |
| `400` | `challenge_invalid` | Any challenge rejection in §4. One code for every cause. |
| `403` | `email_unverified` | Password login under `required` verification, after a correct password only. |
| `429` | `rate_limited` | A per-IP or per-account limit of a new route. |
| `503` | `Rate limiting service temporarily unavailable` | Redis is down and the limit fails closed (same text as login). |
| `422` | FastAPI validation list | Malformed body, unknown field, or password outside policy. |

Existing routes keep their current error shapes. On
`PATCH /profile/update/me/`, `current_password` failures stay
`400 Incorrect password` and `400 current_password is required to change the
email`, and a Google account stays `403`.

## 7. Configuration and feature implications

Settings belong to the service `Settings`, never to the `auth-sdk-m8`
`CommonSettings`. The SDK's `SMTP_HOST`, `SMTP_PORT`, `EMAILS_FROM_EMAIL`, and
`EMAILS_FROM_NAME` are reused unchanged.

| Setting | Default | Notes |
| --- | --- | --- |
| `PASSWORD_LOGIN_ENABLED` | `true` | |
| `GOOGLE_OAUTH_ENABLED` | unset | Unset: Google is on when its credentials are set (`2.2.3` behavior). `true`: credentials required. `false`: Google off even with credentials. |
| `PUBLIC_SIGNUP_ENABLED` | `false` | |
| `PUBLIC_SIGNUP_ALLOWED_EMAIL_DOMAINS` | empty | Optional allowlist; never published. |
| `MAIL_ENABLED` | `false` | |
| `EMAIL_VERIFICATION_MODE` | `off` | `off`, `optional`, `required`. |
| `PASSWORD_RESET_ENABLED` | `false` | |
| `PUBLIC_UI_URL` | empty | Base of every emailed link. |
| `SMTP_USER`, `SMTP_PASSWORD` | empty | `SMTP_PASSWORD` is a `SecretStr`, `*_FILE`-sourceable. |
| `SMTP_TLS_MODE` | `starttls` | `implicit`, `starttls`, `none`. Certificates and hostnames are verified; a STARTTLS failure is fatal, never a plaintext downgrade. |
| `EMAIL_VERIFICATION_TTL_MINUTES` | `1440` | 15 – 1440. |
| `PASSWORD_RESET_TTL_MINUTES` | `30` | 5 – 30. |
| `EMAIL_CHANGE_TTL_MINUTES` | `60` | 10 – 60. |
| `UNVERIFIED_SIGNUP_EXPIRY_DAYS` | `7` | 1 – 30. |
| `MAIL_RECIPIENT_COOLDOWN_SECONDS` | `60` | Per recipient address. |
| `MAIL_RECIPIENT_DAILY_CAP` | `10` | Per recipient address, rolling 24 h. |

Startup fails, with a message that names no secret, when:

- no login method is enabled;
- public signup is on without password login;
- verification is not `off`, or reset is on, without `MAIL_ENABLED`;
- reset is on without password login;
- mail is on without `SMTP_HOST`, `EMAILS_FROM_EMAIL`, or `PUBLIC_UI_URL`;
- mail is on and `PUBLIC_UI_URL` is not HTTPS, unless `ENVIRONMENT=local`;
- mail is on and `ALLOWED_HOSTS` is empty;
- `SMTP_TLS_MODE=none` outside `ENVIRONMENT=local`;
- `GOOGLE_OAUTH_ENABLED=true` without both Google credentials.

With every new setting at its default, the service behaves as `2.2.3`, apart
from the documented `2.2.4` security fixes.

## 8. Compatibility

- The issuer `CONTRACT_VERSION` stays `"2.0"` and `CONTRACT_RANGE` stays
  `>=2.0.0 <3.0.0`. Every new route is additive, so no published client
  breaks.
- Each account-lifecycle stage ships as an `fa-auth-m8` minor release and can
  be rolled back by turning its flag off. Schema changes are expand-only.
- No `auth-sdk-m8` release is needed. The capability, challenge-token, and
  mail types are owned by this service.
- `{API_PREFIX}/meta` keeps its shape. Consumers that check the issuer's
  version against a declared range read `/meta` only; a minor release stays
  inside any range whose upper bound is `<3.0.0`.
- A client adopts the new features by reading the capability document; it
  moves its tested service version explicitly to the release that serves it
  and never widens its service-version range silently.
