from constructs import Construct
from aws_cdk import (
    Stack,
    RemovalPolicy,
    Tags,
    aws_s3 as s3,
    aws_kms as kms,
    aws_sns as sns,
)
from typing import Optional

from .props import SecureS3BucketProps
from .validations import S3Validator, ValidationError
from .compliance import ComplianceChecker
from .kms import KMSKeyManager
from .policies import S3PolicyManager
from .lifecycle import LifecycleManager
from .monitoring import MonitoringManager


class SecureAuditedS3Bucket(Construct):
    """
    Production-ready, HIPAA and CIS 1.8 compliant S3 bucket construct.

    Features:
    - KMS encryption with automatic key rotation
    - Cross-region replication
    - Comprehensive audit logging
    - CloudWatch metrics and alarms
    - SNS alerts for security events
    - Lifecycle policies with Glacier/Deep Archive support
    - MFA delete and versioning options
    - SSL/TLS enforcement
    - Block all public access
    """

    def __init__(
        self, scope: Construct, id: str, props: SecureS3BucketProps
    ) -> None:
        super().__init__(scope, id)

        # Validate input
        try:
            S3Validator.validate_props(props)
        except ValidationError as e:
            raise ValueError(f"Invalid S3 bucket configuration: {e}")

        # Validate compliance
        try:
            ComplianceChecker.validate_compliance(props.compliance)
        except ValueError as e:
            raise ValueError(f"Compliance validation failed: {e}")

        self.props = props
        self.bucket: Optional[s3.Bucket] = None
        self.audit_bucket: Optional[s3.Bucket] = None
        self.kms_key: Optional[kms.Key] = None
        self.audit_kms_key: Optional[kms.Key] = None
        self.sns_topic: Optional[sns.Topic] = None

        # Compute audit bucket name once to ensure consistency across all components
        self._audit_bucket_name = (
            self.props.audit_bucket_name
            or f"{self.props.bucket_name}-audit-{Stack.of(self).account}"
        )

        # Build the construct
        self._create_kms_keys()
        self._create_audit_bucket()
        self._create_data_bucket()
        self._configure_policies()
        self._setup_lifecycle()
        self._setup_monitoring()

    def _create_kms_keys(self) -> None:
        """Create KMS keys for encryption."""
        if self.props.compliance.enforce_encryption and self.props.kms.enable_kms:
            self.kms_key = KMSKeyManager.create_s3_key(
                self,
                "s3-kms-key",
                self.props.kms,
                self.props.bucket_name,
            )

            self.audit_kms_key = KMSKeyManager.create_audit_bucket_key(
                self,
                "audit-s3-kms-key",
                self.props.kms,
                self._audit_bucket_name,
            )

    def _create_audit_bucket(self) -> None:
        """Create audit/logging bucket."""
        self.audit_bucket = s3.Bucket(
            self,
            "audit-bucket",
            bucket_name=self._audit_bucket_name,
            versioning_enabled=self.props.enable_versioning,
            block_public_access=s3.BlockPublicAccess(
                block_public_acls=True,
                block_public_policy=True,
                ignore_public_acls=True,
                restrict_public_buckets=True,
            ),
            encryption=s3.BucketEncryption.KMS if self.audit_kms_key else s3.BucketEncryption.S3_MANAGED,
            encryption_key=self.audit_kms_key,
            enforce_ssl=self.props.compliance.enforce_ssl_only,
            lifecycle_rules=LifecycleManager.create_audit_bucket_lifecycle_rules(
                self.props.monitoring.cloudwatch_log_retention_days
            ),
            removal_policy=RemovalPolicy[self.props.removal_policy],
        )

        # Note: Audit bucket self-logging (audit logs logging to itself) is not configured.
        # CDK L2 Bucket construct doesn't support self-referential server_access_logs_bucket.
        # To enable after stack deployment, use AWS CLI:
        # aws s3api put-bucket-logging --bucket <name> --bucket-logging-status LoggingEnabled={TargetBucket=<name>,TargetPrefix=<prefix>}

        # Tag audit bucket
        Tags.of(self.audit_bucket).add("bucket-type", "audit")
        Tags.of(self.audit_bucket).add("environment", self.props.environment)

    def _create_data_bucket(self) -> None:
        """Create main data bucket."""
        self.bucket = s3.Bucket(
            self,
            "s3-bucket",
            bucket_name=self.props.bucket_name,
            versioning_enabled=self.props.compliance.enforce_versioning or self.props.enable_versioning,
            block_public_access=s3.BlockPublicAccess(
                block_public_acls=self.props.compliance.block_all_public_access,
                block_public_policy=self.props.compliance.block_all_public_access,
                ignore_public_acls=self.props.compliance.block_all_public_access,
                restrict_public_buckets=self.props.compliance.block_all_public_access,
            ),
            encryption=s3.BucketEncryption.KMS if self.kms_key else s3.BucketEncryption.S3_MANAGED,
            encryption_key=self.kms_key,
            enforce_ssl=self.props.compliance.enforce_ssl_only,
            server_access_logs_bucket=self.audit_bucket,
            server_access_logs_prefix=self.props.monitoring.log_prefix,
            lifecycle_rules=LifecycleManager.create_lifecycle_rules(
                self.props.lifecycle
            ),
            removal_policy=RemovalPolicy[self.props.removal_policy],
        )

        # Tag bucket for resource management and governance
        Tags.of(self.bucket).add("bucket-type", "data")
        Tags.of(self.bucket).add("environment", self.props.environment)
        Tags.of(self.bucket).add("project", self.props.project_name)

        # Add compliance framework tags (HIPAA, CIS 1.8, encryption status, etc.)
        compliance_tags = ComplianceChecker.get_compliance_tags(
            self.props.compliance
        )
        for key, value in compliance_tags.items():
            Tags.of(self.bucket).add(key, value)

        # Add user-provided custom tags
        for key, value in self.props.tags.items():
            Tags.of(self.bucket).add(key, value)

    def _configure_policies(self) -> None:
        """Configure bucket policies for security."""
        if not self.bucket or not self.audit_bucket:
            return

        # Configure main bucket policies
        S3PolicyManager.configure_bucket_policies(
            self.bucket,
            self.props,
            self.kms_key,
            is_audit_bucket=False,
        )

        # Configure audit bucket policies
        # add_audit_bucket_policy() already calls add_encryption_enforcement() and add_ssl_enforcement(),
        # so we only need to add the delete protection via add_deny_delete_policy()
        S3PolicyManager.add_audit_bucket_policy(
            self.audit_bucket,
            self.bucket,
            self.audit_kms_key,
            self.props.external_audit_account_id,
        )

        # Add delete protection to audit bucket (without duplicating encryption/ssl policies)
        S3PolicyManager.add_deny_delete_policy(self.audit_bucket)

        # Restrict data-bucket access to configured VPC network paths (endpoint or source-based).
        # VPC endpoint IDs (preferred) are used if specified; otherwise fall back to VPC source IDs.
        # Note: Endpoint IDs and VPC IDs are mutually exclusive—only one restriction method is applied.
        if self.props.vpc_access.restrict_to_vpc:
            if self.props.vpc_access.allowed_vpc_endpoints:
                S3PolicyManager.add_vpc_endpoint_enforcement(
                    self.bucket,
                    self.props.vpc_access.allowed_vpc_endpoints,
                )
            else:
                S3PolicyManager.add_vpc_source_enforcement(
                    self.bucket,
                    self.props.vpc_access.allowed_vpc_ids,
                )

        # Add cross-account data ingestion policy (PutObject only, requires KMS encryption)
        if self.props.vpc_access.allow_cross_account_ingestion and self.props.vpc_access.cross_account_principals:
            S3PolicyManager.add_cross_account_ingestion(
                self.bucket,
                self.props.vpc_access.cross_account_principals,
                self.kms_key,
            )

    def _setup_lifecycle(self) -> None:
        """Lifecycle rules are set during bucket creation."""
        pass

    def _setup_monitoring(self) -> None:
        """Setup CloudWatch, SNS, and logging."""
        if not self.bucket or not self.audit_bucket:
            return

        # Setup bucket logging
        MonitoringManager.setup_bucket_logging(
            self,
            self.bucket,
            self.audit_bucket,
            self.props.monitoring,
            self.kms_key,
        )

        # Setup audit bucket logging
        MonitoringManager.create_audit_bucket_logging(
            self,
            self.audit_bucket,
            self.props.monitoring,
            self.audit_kms_key,
        )

        # Create SNS topic if alerts enabled (use data bucket's KMS key for encryption)
        if self.props.monitoring.enable_sns_alerts:
            self.sns_topic = MonitoringManager.create_sns_topic(
                self,
                "security-alerts-topic",
                self.props.monitoring.sns_topic_name,
                self.kms_key,
            )

        if self.props.monitoring.enable_cloudwatch_alarms:
            # Create access/performance alarms
            MonitoringManager.create_cloudwatch_alarms(
                self,
                self.bucket,
                f"{self.props.bucket_name}-alarms",
                self.sns_topic,
                self.props.monitoring,
            )

            # Create alarms for accidental public exposure attempts
            MonitoringManager.create_public_exposure_alarms(
                self,
                self.props.bucket_name,
                self.audit_bucket,
                self.kms_key,
                self.sns_topic,
            )

    # Properties for accessing bucket resources
    @property
    def bucket_name(self) -> str:
        """Return the data bucket name."""
        return self.bucket.bucket_name if self.bucket else ""

    @property
    def bucket_arn(self) -> str:
        """Return the data bucket ARN."""
        return self.bucket.bucket_arn if self.bucket else ""

    @property
    def audit_bucket_name(self) -> str:
        """Return the audit bucket name."""
        return self.audit_bucket.bucket_name if self.audit_bucket else ""

    @property
    def audit_bucket_arn(self) -> str:
        """Return the audit bucket ARN."""
        return self.audit_bucket.bucket_arn if self.audit_bucket else ""

    @property
    def kms_key_id(self) -> Optional[str]:
        """Return the KMS key ID."""
        return self.kms_key.key_id if self.kms_key else None

    @property
    def kms_key_arn(self) -> Optional[str]:
        """Return the KMS key ARN."""
        return self.kms_key.key_arn if self.kms_key else None

    @property
    def topic_arn(self) -> Optional[str]:
        """Return the SNS topic ARN."""
        return self.sns_topic.topic_arn if self.sns_topic else None
