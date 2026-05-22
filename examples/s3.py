"""
Example usage of SecureAuditedS3Bucket construct.

This file demonstrates various configurations for the reusable S3 module.
"""

import aws_cdk as cdk
from secure_aws.s3 import (
    SecureAuditedS3Bucket,
    SecureS3BucketProps,
    KMSProps,
    LifecycleProps,
    MonitoringProps,
    ComplianceProps,
    ComplianceMode,
)


# Example 1: Minimal HIPAA-compliant bucket (strict defaults)
def example_hipaa_minimal(stack: cdk.Stack) -> SecureAuditedS3Bucket:
    """
    Minimal configuration with strict HIPAA compliance.
    Uses all secure defaults.
    """
    props = SecureS3BucketProps(
        bucket_name="healthcare-data-prod",
        environment="production",
        project_name="patient-records",
        audit_bucket_name="healthcare-data-prod-audit",
    )

    return SecureAuditedS3Bucket(stack, "hipaa-bucket", props)


# Example 2: Healthcare bucket that permits external log delivery
def example_hipaa_external_log_delivery(stack: cdk.Stack) -> SecureAuditedS3Bucket:
    """
    Healthcare bucket whose locally managed audit bucket can accept
    S3 log delivery from a dedicated external audit account.
    """
    props = SecureS3BucketProps(
        bucket_name="patient-data-prod",
        environment="production",
        project_name="ehr-system",
        external_audit_account_id="111111111111",  # Account allowed to deliver logs into the local audit bucket
        monitoring=MonitoringProps(
            enable_access_logging=True,
            enable_sns_alerts=True,
            sns_topic_name="healthcare-security-alerts",
        ),
        tags={
            "data-classification": "PHI",
            "compliance-owner": "security@company.com",
        },
    )

    return SecureAuditedS3Bucket(stack, "healthcare-bucket", props)


# Example 3: Financial data with extended retention
def example_financial_data(stack: cdk.Stack) -> SecureAuditedS3Bucket:
    """
    Financial services bucket with 7-year retention (2555 days).
    Includes Glacier and Deep Archive transitions.
    """
    props = SecureS3BucketProps(
        bucket_name="financial-records-prod",
        environment="production",
        project_name="accounting-system",
        lifecycle=LifecycleProps(
            retention_days=2555,  # 7 years for regulatory retention
            enable_intelligent_tiering=False,
            glacier_transition_enabled=True,
            glacier_transition_days=365,  # Move to Glacier after 1 year
            deep_archive_transition_enabled=True,
            deep_archive_transition_days=1095,  # Move to Deep Archive after 3 years
        ),
        tags={
            "data-classification": "CONFIDENTIAL",
            "regulatory-retention": "7-years",
        },
    )

    return SecureAuditedS3Bucket(stack, "financial-bucket", props)


# Example 4: Log aggregation bucket with short retention
def example_log_aggregation(stack: cdk.Stack) -> SecureAuditedS3Bucket:
    """
    Log aggregation bucket with 90-day retention.
    Optimized for cost with Intelligent Tiering.
    """
    props = SecureS3BucketProps(
        bucket_name="application-logs-prod",
        environment="production",
        project_name="log-aggregation",
        lifecycle=LifecycleProps(
            retention_days=90,
            enable_intelligent_tiering=True,
            glacier_transition_enabled=False,
        ),
        compliance=ComplianceProps(
            enforce_compliance=True,
            compliance_mode=ComplianceMode.RECOMMENDED,
        ),
        enable_versioning=False,
    )

    return SecureAuditedS3Bucket(stack, "logs-bucket", props)


# Example 5: Development environment with relaxed settings
def example_development_bucket(stack: cdk.Stack) -> SecureAuditedS3Bucket:
    """
    Development environment - still secure but less strict.
    Uses recommended compliance mode for flexibility.
    """
    props = SecureS3BucketProps(
        bucket_name="dev-sandbox-data",
        environment="development",
        project_name="dev-testing",
        lifecycle=LifecycleProps(
            retention_days=30,
            enable_intelligent_tiering=False,
        ),
        monitoring=MonitoringProps(
            enable_access_logging=True,
            enable_cloudwatch_alarms=False,  # Less monitoring in dev
            enable_sns_alerts=False,
        ),
        compliance=ComplianceProps(
            enforce_compliance=True,
            compliance_mode=ComplianceMode.RECOMMENDED,  # More flexible
        ),
        enable_versioning=True,
    )

    return SecureAuditedS3Bucket(stack, "dev-bucket", props)


# Example 6: Custom KMS configuration
def example_custom_kms_bucket(stack: cdk.Stack) -> SecureAuditedS3Bucket:
    """
    Custom KMS configuration with a non-default rotation period.
    """
    props = SecureS3BucketProps(
        bucket_name="high-security-data",
        environment="production",
        project_name="critical-assets",
        kms=KMSProps(
            enable_kms=True,
            key_rotation_enabled=True,
            key_rotation_period_days=180,  # Rotate every 6 months
            key_alias_prefix="critical-data",
        ),
        tags={
            "encryption-tier": "critical",
            "rotation-frequency": "semiannual",
        },
    )

    return SecureAuditedS3Bucket(stack, "critical-bucket", props)


# Example 7: Multi-region-ready bucket metadata
def example_multi_region_ready_bucket(stack: cdk.Stack) -> SecureAuditedS3Bucket:
    """
    Bucket tagged for a future multi-region rollout.
    This construct does not configure replication by itself.
    """
    props = SecureS3BucketProps(
        bucket_name="multi-region-data",
        environment="production",
        project_name="global-application",
        monitoring=MonitoringProps(
            enable_access_logging=True,
            enable_sns_alerts=True,
        ),
        tags={
            "multi-region": "true",
            "rpo-days": "1",  # Recovery Point Objective
            "rto-hours": "4",  # Recovery Time Objective
        },
    )

    return SecureAuditedS3Bucket(stack, "multi-region-bucket", props)


# Stack example showing multiple buckets
class SecureS3Stack(cdk.Stack):
    """Example CDK stack with multiple secure buckets."""

    def __init__(self, scope: cdk.App, id: str, **kwargs) -> None:
        super().__init__(scope, id, **kwargs)

        # Healthcare bucket
        healthcare = example_hipaa_minimal(self)

        # Financial bucket
        financial = example_financial_data(self)

        # Logs bucket
        logs = example_log_aggregation(self)

        # Output important values
        cdk.CfnOutput(
            self,
            "HealthcareBucket",
            value=healthcare.bucket_name,
            description="Healthcare data bucket name",
        )

        cdk.CfnOutput(
            self,
            "FinancialBucket",
            value=financial.bucket_name,
            description="Financial records bucket name",
        )

        cdk.CfnOutput(
            self,
            "LogsBucket",
            value=logs.bucket_name,
            description="Application logs bucket name",
        )

        cdk.CfnOutput(
            self,
            "HealthcareKMSKey",
            value=healthcare.kms_key_arn or "No KMS key",
            description="Healthcare bucket KMS key ARN",
        )


# Usage in app
def main():
    """Deploy the example stacks."""
    app = cdk.App()

    SecureS3Stack(
        app,
        "secure-s3-stack",
        env=cdk.Environment(
            account="111111111111",  # Replace with your AWS account ID
            region="us-east-1",
        ),
    )

    app.synth()


if __name__ == "__main__":
    main()
