import re
from typing import Optional
from .props import SecureS3BucketProps, ComplianceMode


class ValidationError(Exception):
    """Custom validation error."""
    pass


class S3Validator:
    """Validates S3 bucket configuration."""

    @staticmethod
    def validate_bucket_name(bucket_name: str) -> None:
        """Validate S3 bucket name format."""
        if not bucket_name:
            raise ValidationError("Bucket name cannot be empty")

        if len(bucket_name) < 3 or len(bucket_name) > 63:
            raise ValidationError(
                f"Bucket name must be 3-63 characters. Got: {len(bucket_name)}"
            )

        if not re.match(r"^[a-z0-9.-]+$", bucket_name):
            raise ValidationError(
                "Bucket name must contain only lowercase letters, numbers, dots, and hyphens"
            )

        if bucket_name.startswith("-") or bucket_name.endswith("-"):
            raise ValidationError("Bucket name cannot start or end with a hyphen")

        if bucket_name.startswith(".") or bucket_name.endswith("."):
            raise ValidationError("Bucket name cannot start or end with a dot")

        if ".." in bucket_name:
            raise ValidationError("Bucket name cannot contain consecutive dots")

        if re.match(r"^\d+\.\d+\.\d+\.\d+$", bucket_name):
            raise ValidationError("Bucket name cannot be formatted as an IP address")

    @staticmethod
    def validate_retention_days(retention_days: int) -> None:
        """Validate retention days."""
        if retention_days < 1:
            raise ValidationError("Retention days must be at least 1")

        if retention_days > 3650:  # 10 years
            raise ValidationError("Retention days should not exceed 3650 (10 years)")

    @staticmethod
    def validate_aws_account_id(account_id: str) -> None:
        """Validate AWS account ID format."""
        if not re.match(r"^\d{12}$", account_id):
            raise ValidationError(
                f"Invalid AWS account ID format: {account_id}. Must be 12 digits."
            )

    @staticmethod
    def validate_arn_format(arn: str) -> None:
        """Validate AWS ARN format.

        Supports both account-specific and AWS-managed resources:
        - Account-specific: arn:partition:service:region:account-id:resource
        - AWS-managed: arn:partition:service:region::resource (empty account ID)
        """
        # Allow optional account ID (empty for AWS-managed resources) and resource names with digits/mixed-case
        if not re.match(r"^arn:aws(:[a-z\-]*)?:[a-z0-9\-]+:[a-z0-9\-]*:\d*:[a-z0-9:/_\-*.]+$", arn, re.IGNORECASE):
            raise ValidationError(f"Invalid ARN format: {arn}")

    @staticmethod
    def validate_vpc_endpoint_id(endpoint_id: str) -> None:
        """Validate VPC endpoint ID format."""
        if not re.match(r"^vpce-[a-z0-9]+$", endpoint_id):
            raise ValidationError(f"Invalid VPC endpoint ID format: {endpoint_id}. Must be vpce-XXXXXXXX")

    @staticmethod
    def validate_vpc_id(vpc_id: str) -> None:
        """Validate VPC ID format."""
        if not re.match(r"^vpc-[a-z0-9]+$", vpc_id):
            raise ValidationError(
                f"Invalid VPC ID format: {vpc_id}. Must be vpc-XXXXXXXX"
            )

    @staticmethod
    def validate_props(props: SecureS3BucketProps) -> None:
        """Validate all properties."""
        # Validate bucket names
        S3Validator.validate_bucket_name(props.bucket_name)

        if props.audit_bucket_name:
            S3Validator.validate_bucket_name(props.audit_bucket_name)

        # Validate retention
        S3Validator.validate_retention_days(props.lifecycle.retention_days)

        if props.lifecycle.noncurrent_version_expiration_days:
            S3Validator.validate_retention_days(
                props.lifecycle.noncurrent_version_expiration_days
            )

        # Validate external account if specified
        if props.external_audit_account_id:
            S3Validator.validate_aws_account_id(props.external_audit_account_id)

        # Validate lifecycle transition timing: objects must transition to Glacier before expiring
        if props.lifecycle.glacier_transition_enabled:
            if props.lifecycle.glacier_transition_days > props.lifecycle.retention_days:
                raise ValidationError(
                    f"Glacier transition days ({props.lifecycle.glacier_transition_days}) "
                    f"must be < retention days ({props.lifecycle.retention_days})"
                )

        # Validate deep archive requires glacier (AWS minimum storage duration: Glacier 90 days, Deep Archive 180 days)
        if props.lifecycle.deep_archive_transition_enabled:
            if not props.lifecycle.glacier_transition_enabled:
                raise ValidationError(
                    "deep_archive_transition_enabled requires glacier_transition_enabled to be True"
                )
            if props.lifecycle.deep_archive_transition_days < props.lifecycle.glacier_transition_days:
                raise ValidationError(
                    f"Deep archive transition days ({props.lifecycle.deep_archive_transition_days}) "
                    f"must be >= glacier transition days ({props.lifecycle.glacier_transition_days})"
                )

        # Validate KMS rotation period
        if props.kms.key_rotation_enabled:
            if props.kms.key_rotation_period_days < 90 or props.kms.key_rotation_period_days > 2555:
                raise ValidationError(
                    f"KMS key rotation period must be 90-2555 days. Got: {props.kms.key_rotation_period_days}"
                )

        # Validate removal policy
        valid_policies = {"RETAIN", "DESTROY", "SNAPSHOT"}
        if props.removal_policy not in valid_policies:
            raise ValidationError(
                f"removal_policy must be one of {valid_policies}. Got: {props.removal_policy!r}"
            )
        if props.compliance.compliance_mode == ComplianceMode.STRICT and props.removal_policy != "RETAIN":
            raise ValidationError(
                "STRICT compliance mode requires removal_policy to be 'RETAIN' to prevent accidental data loss"
            )

        # Strict compliance checks
        if props.compliance.compliance_mode == ComplianceMode.STRICT:
            if not props.compliance.enforce_encryption:
                raise ValidationError(
                    "STRICT compliance mode requires encryption to be enforced"
                )

            if not props.compliance.block_all_public_access:
                raise ValidationError(
                    "STRICT compliance mode requires blocking all public access"
                )

            if not props.compliance.enforce_ssl_only:
                raise ValidationError(
                    "STRICT compliance mode requires SSL-only access"
                )

            if not props.compliance.enforce_versioning:
                raise ValidationError(
                    "STRICT compliance mode requires versioning to be enforced"
                )

            if not props.kms.enable_kms:
                raise ValidationError(
                    "STRICT compliance mode requires KMS encryption"
                )

            if not props.monitoring.enable_access_logging:
                raise ValidationError(
                    "STRICT compliance mode requires access logging"
                )

        # Replication validation
        if props.replication.enable_replication:
            if not props.replication.destination_region:
                raise ValidationError(
                    "Replication enabled but destination_region not specified"
                )
            if not props.replication.destination_bucket_name:
                raise ValidationError(
                    "Replication enabled but destination_bucket_name not specified"
                )
            S3Validator.validate_bucket_name(props.replication.destination_bucket_name)

        # Note: audit_bucket_name is auto-generated if empty
        # No validation needed here since construct handles it

        # VPC access validation
        if props.vpc_access.cross_account_principals:
            for arn in props.vpc_access.cross_account_principals:
                S3Validator.validate_arn_format(arn)

        if props.vpc_access.allowed_vpc_endpoints:
            for endpoint_id in props.vpc_access.allowed_vpc_endpoints:
                S3Validator.validate_vpc_endpoint_id(endpoint_id)

        if props.vpc_access.allowed_vpc_ids:
            for vpc_id in props.vpc_access.allowed_vpc_ids:
                S3Validator.validate_vpc_id(vpc_id)

        if props.vpc_access.restrict_to_vpc:
            if (
                not props.vpc_access.allowed_vpc_endpoints
                and not props.vpc_access.allowed_vpc_ids
            ):
                raise ValidationError(
                    "restrict_to_vpc=True requires at least one allowed_vpc_endpoint "
                    "or allowed_vpc_id"
                )
