from enum import Enum


class ComplianceMode(str, Enum):
    """Compliance enforcement level used across all secure_aws modules.

    STRICT  — raise an error if any compliance requirement is violated.
    RECOMMENDED — emit a warning but allow deployment to proceed.
    """

    STRICT = "strict"
    RECOMMENDED = "recommended"
