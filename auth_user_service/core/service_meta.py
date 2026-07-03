"""Static service/contract metadata for the fa-auth-m8 issuer ``/meta`` route.

fa-auth-m8 is the **issuer**: it builds its own FastAPI app rather than going
through ``fastapi_m8.create_app``, so it mounts the shared ``/meta`` + ``/ping``
routes itself by calling ``auth_sdk_m8.controllers.meta.mount_service_meta`` with
the metadata built here. These values are properties of the API contract this
service implements (mirrored by ``@fa-m8/astro-auth-m8``'s ``compatibility``
module), so they live in code, not env.
"""

from auth_sdk_m8.schemas.meta import ServiceContract, ServiceMeta

from auth_user_service import __version__

#: Service identity (also the contract id).
SERVICE_NAME = "fa-auth-m8"
#: Public API version label.
API_VERSION = "v1"
#: Contract version the plugin pins (astro-auth-m8 FA_AUTH_M8_CONTRACT_VERSION).
CONTRACT_VERSION = "1.0"
#: Compatible service-version range. Lower bound raised to 1.0.0 — the first
#: stable line, which retires the legacy single-``PRIVATE_API_SECRET`` private-API
#: gate in favour of per-consumer scoped credentials / short-TTL service tokens
#: (on top of the 0.9.x security-remediation baseline). Consumers should pin to
#: the 1.x line.
CONTRACT_RANGE = ">=1.0.0 <2.0.0"


def build_service_meta() -> ServiceMeta:
    """Build the issuer's public ``ServiceMeta`` served at ``{API_PREFIX}/meta``.

    Public + minimal: service/version/contract only — no build or internal data.
    The service version tracks the package ``__version__``.
    """
    return ServiceMeta(
        service=SERVICE_NAME,
        version=__version__,
        api_version=API_VERSION,
        contract=ServiceContract(
            name=SERVICE_NAME,
            version=CONTRACT_VERSION,
            range=CONTRACT_RANGE,
        ),
    )
