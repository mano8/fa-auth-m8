"""fastapi_full fastapi app db models"""

from .categories import Category as Category
from .privileged_action_audit import (
    AuditAction as AuditAction,
    PrivilegedActionAudit as PrivilegedActionAudit,
)
