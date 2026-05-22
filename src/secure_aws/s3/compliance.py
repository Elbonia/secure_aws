from typing import List
from .props import ComplianceProps, ComplianceMode


class ComplianceChecker:
    """Validates HIPAA and CIS 1.8 compliance requirements."""

    HIPAA_REQUIREMENTS = {
        "encryption_at_rest": "S3 buckets must have encryption at rest enabled",
        "encryption_in_transit": "S3 buckets must enforce encryption in transit (SSL/TLS)",
        "access_logging": "S3 buckets must have access logging enabled",
        "versioning": "S3 buckets should have versioning enabled for data recovery",
        "block_public_access": "S3 buckets must block all public access",
    }

    CIS_1_8_REQUIREMENTS = {
        "versioning": "CIS 1.8.2: Enable S3 Bucket Versioning",
        "public_access": "CIS 1.8.1: Ensure S3 bucket blocks all public access",
        "logging": "CIS 1.8.4: Ensure S3 bucket has access logging enabled",
        "ssl_only": "CIS 1.8.5: Ensure S3 Bucket enforces SSL/TLS Request",
    }

    @staticmethod
    def check_hipaa_compliance(compliance: ComplianceProps) -> List[str]:
        """Check HIPAA compliance requirements."""
        violations = []

        if not compliance.enforce_encryption:
            violations.append(ComplianceChecker.HIPAA_REQUIREMENTS["encryption_at_rest"])

        if not compliance.enforce_ssl_only:
            violations.append(ComplianceChecker.HIPAA_REQUIREMENTS["encryption_in_transit"])

        if not compliance.block_all_public_access:
            violations.append(ComplianceChecker.HIPAA_REQUIREMENTS["block_public_access"])

        return violations

    @staticmethod
    def check_cis_1_8_compliance(compliance: ComplianceProps) -> List[str]:
        """Check CIS 1.8 compliance requirements."""
        violations = []

        if not compliance.enforce_versioning:
            violations.append(ComplianceChecker.CIS_1_8_REQUIREMENTS["versioning"])

        if not compliance.block_all_public_access:
            violations.append(ComplianceChecker.CIS_1_8_REQUIREMENTS["public_access"])

        if not compliance.enforce_ssl_only:
            violations.append(ComplianceChecker.CIS_1_8_REQUIREMENTS["ssl_only"])

        return violations

    @staticmethod
    def validate_compliance(compliance: ComplianceProps) -> None:
        """Validate compliance based on mode."""
        if not compliance.enforce_compliance:
            return

        all_violations = []
        all_violations.extend(ComplianceChecker.check_hipaa_compliance(compliance))
        all_violations.extend(ComplianceChecker.check_cis_1_8_compliance(compliance))

        if compliance.compliance_mode == ComplianceMode.STRICT and all_violations:
            raise ValueError(
                f"Compliance violations detected in STRICT mode:\n"
                + "\n".join(f"  - {v}" for v in all_violations)
            )

        if compliance.compliance_mode == ComplianceMode.RECOMMENDED and all_violations:
            print(
                f"⚠️  Compliance warnings detected:\n"
                + "\n".join(f"  - {v}" for v in all_violations)
            )

    @staticmethod
    def get_compliance_tags(compliance: ComplianceProps) -> dict:
        """Generate tags for compliance tracking and governance.

        Tags indicate actual compliance status (based on violations found) and which controls are enabled.
        These are applied to S3 buckets for resource inventory and policy management.
        """
        tags = {
            "compliance-mode": compliance.compliance_mode.value,
        }

        if compliance.enforce_compliance:
            # Only tag as compliant if no violations are found
            hipaa_violations = ComplianceChecker.check_hipaa_compliance(compliance)
            cis_violations = ComplianceChecker.check_cis_1_8_compliance(compliance)

            tags["hipaa-compliant"] = "true" if not hipaa_violations else "false"
            tags["cis-1-8-compliant"] = "true" if not cis_violations else "false"

        # Add tags for enabled security controls
        if compliance.enforce_encryption:
            tags["encryption"] = "enabled"

        if compliance.enforce_ssl_only:
            tags["ssl-required"] = "true"

        if compliance.enforce_versioning:
            tags["versioning"] = "enabled"

        return tags
