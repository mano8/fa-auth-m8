"""Test bootstrap for the bundled ``fastapi_full`` consumer example.

``fastapi_full.core.config`` validates its settings at import time and fails
fast when the configuration is incomplete, so a deterministic environment has
to exist before the first ``fastapi_full`` import. Environment variables
outrank any developer ``.env`` sitting next to the example, which keeps this
suite identical locally and in CI (where no ``.env`` is checked in).

Every value here is a throwaway local-profile placeholder: no test in this
suite opens a socket or a database connection.
"""

from __future__ import annotations

import os

_TEST_ENV = {
    "DOMAIN": "localhost",
    "ENVIRONMENT": "local",
    "PROJECT_NAME": "fastapi-full-tests",
    "STACK_NAME": "fastapi-full-tests",
    "API_PREFIX": "/fastapi",
    "BACKEND_HOST": "http://127.0.0.1:9000",
    "FRONTEND_HOST": "http://localhost:5173",
    "BACKEND_CORS_ORIGINS": "http://localhost:9000",
    "AUTH_SERVICE_ROLE": "consumer",
    "AUTH_PREFIX": "/user",
    "SELECTED_DB": "Postgres",
    "DB_HOST": "127.0.0.1",
    "DB_PORT": "5432",
    "DB_DATABASE": "api_db",
    "DB_USER": "example_tests_user",
    "DB_PASSWORD": "ExampleTests_Passw0rd",
    "SECRET_KEY": "ExampleTests-SessionSecret-fa8full-Ab1",
    "ACCESS_SECRET_KEY": "ExampleTests-AccessKey-fa8full-Ab12Cd",
    "REFRESH_SECRET_KEY": "ExampleTests-RefreshKey-fa8full-Ab12Cd",
    "ACCESS_TOKEN_ALGORITHM": "HS256",
    "REFRESH_TOKEN_ALGORITHM": "HS256",
    "TOKEN_MODE": "stateless",
    "TOKEN_STRICT_VALIDATION": "false",
    "EVENT_SIGNING_ENABLED": "false",
    "METRICS_ENABLED": "false",
}

for _key, _value in _TEST_ENV.items():
    os.environ[_key] = _value
