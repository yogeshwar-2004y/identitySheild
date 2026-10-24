"""Rule registry. Add a rule by writing a `Rule` subclass and listing it here."""
from __future__ import annotations

from app.detection.base import Rule
from app.detection.rules.auth import BruteForce, CredentialStuffing, ImpossibleTravel, MfaFatigue, OffHoursAccess
from app.detection.rules.identity import DelayedDeprovisioning, GhostAccount, OrphanedAccount, PrivilegeEscalation
from app.detection.rules.session import MassAccess, RefreshTokenReuse, SessionHijack

RULE_CLASSES: dict[str, type[Rule]] = {
    cls.key: cls
    for cls in [
        ImpossibleTravel, SessionHijack, RefreshTokenReuse, GhostAccount, OrphanedAccount, PrivilegeEscalation,
        BruteForce, CredentialStuffing, MfaFatigue, OffHoursAccess, MassAccess, DelayedDeprovisioning,
    ]
}
