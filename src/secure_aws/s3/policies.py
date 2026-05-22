from aws_cdk import (
    Stack,
    aws_s3 as s3,
    aws_iam as iam,
    aws_kms as kms,
)
from typing import Optional
from .props import SecureS3BucketProps


class S3PolicyManager:
    """Manages S3 bucket policies and encryption enforcement."""

    @staticmethod
    def add_encryption_enforcement(
        bucket: s3.Bucket,
        kms_key: Optional[kms.Key],
    ) -> None:
        """Add bucket policies to enforce KMS encryption for all object uploads.

        This prevents unencrypted uploads and enforces use of a specific KMS key.
        """
        # Deny all uploads that don't use KMS encryption
        bucket.add_to_resource_policy(
            iam.PolicyStatement(
                sid="DenyUnencryptedObjectUploads",
                effect=iam.Effect.DENY,
                principals=[iam.AnyPrincipal()],
                actions=["s3:PutObject"],
                resources=[bucket.arn_for_objects("*")],
                conditions={
                    "StringNotEquals": {
                        "s3:x-amz-server-side-encryption": "aws:kms",
                    }
                },
            )
        )

        if kms_key:
            # Deny uploads that don't use the specific KMS key (enforce key rotation)
            bucket.add_to_resource_policy(
                iam.PolicyStatement(
                    sid="DenyIncorrectKmsKey",
                    effect=iam.Effect.DENY,
                    principals=[iam.AnyPrincipal()],
                    actions=["s3:PutObject"],
                    resources=[bucket.arn_for_objects("*")],
                    conditions={
                        "StringNotEquals": {
                            "s3:x-amz-server-side-encryption-aws-kms-key-id": kms_key.key_arn,
                        }
                    },
                )
            )

    @staticmethod
    def add_ssl_enforcement(bucket: s3.Bucket) -> None:
        """Add bucket policy to deny all unencrypted (HTTP) access.

        Enforces that all S3 API calls must use TLS/HTTPS transport.
        """
        bucket.add_to_resource_policy(
            iam.PolicyStatement(
                sid="DenyInsecureTransport",
                effect=iam.Effect.DENY,
                principals=[iam.AnyPrincipal()],
                actions=["s3:*"],
                resources=[
                    bucket.bucket_arn,
                    bucket.arn_for_objects("*"),
                ],
                conditions={
                    "Bool": {
                        "aws:SecureTransport": "false",
                    }
                },
            )
        )

    @staticmethod
    def add_vpc_endpoint_enforcement(
        bucket: s3.Bucket,
        vpc_endpoint_ids: list,
    ) -> None:
        """Restrict bucket access to only specified VPC endpoints (prevent data exfiltration).

        This policy denies all S3 operations from sources outside the allowed VPC endpoints.
        """
        if not vpc_endpoint_ids:
            return

        # Deny all access from sources not using the specified VPC endpoints
        # This forces all access through the configured private endpoints
        bucket.add_to_resource_policy(
            iam.PolicyStatement(
                sid="DenyAccessOutsideVPCEndpoint",
                effect=iam.Effect.DENY,
                principals=[iam.AnyPrincipal()],
                actions=["s3:*"],
                resources=[
                    bucket.bucket_arn,
                    bucket.arn_for_objects("*"),
                ],
                conditions={
                    "StringNotEquals": {
                        "aws:SourceVpce": vpc_endpoint_ids,
                    }
                },
            )
        )

    @staticmethod
    def add_vpc_source_enforcement(
        bucket: s3.Bucket,
        vpc_ids: list,
    ) -> None:
        """Restrict bucket access to requests originating only from specified VPCs.

        This is a fallback when VPC endpoints are not specified. It blocks access from
        requests outside the specified VPCs (used with VPC peering or same-VPC access).
        """
        if not vpc_ids:
            return

        # Deny all access from sources outside the specified VPCs
        bucket.add_to_resource_policy(
            iam.PolicyStatement(
                sid="DenyAccessOutsideSourceVPC",
                effect=iam.Effect.DENY,
                principals=[iam.AnyPrincipal()],
                actions=["s3:*"],
                resources=[
                    bucket.bucket_arn,
                    bucket.arn_for_objects("*"),
                ],
                conditions={
                    "StringNotEquals": {
                        "aws:SourceVpc": vpc_ids,
                    }
                },
            )
        )

    @staticmethod
    def add_cross_account_ingestion(
        bucket: s3.Bucket,
        cross_account_principals: list,
        kms_key=None,
    ) -> None:
        """Allow cross-account write access (PutObject only) with mandatory KMS encryption.

        Cross-account principals can upload objects but cannot read, delete, or modify
        existing data. All uploads must use the specified KMS key.
        """
        if not cross_account_principals:
            return

        # Build conditions requiring KMS encryption
        conditions: dict = {
            "StringEquals": {
                "s3:x-amz-server-side-encryption": "aws:kms",
            }
        }
        # If a specific KMS key is provided, require its use
        if kms_key:
            conditions["StringEquals"]["s3:x-amz-server-side-encryption-aws-kms-key-id"] = kms_key.key_arn

        # Grant write-only access to specified cross-account principals
        bucket.add_to_resource_policy(
            iam.PolicyStatement(
                sid="AllowCrossAccountDataIngestion",
                effect=iam.Effect.ALLOW,
                principals=[
                    iam.ArnPrincipal(arn) for arn in cross_account_principals
                ],
                actions=["s3:PutObject"],
                resources=[bucket.arn_for_objects("*")],
                conditions=conditions,
            )
        )

    @staticmethod
    def add_audit_bucket_policy(
        audit_bucket: s3.Bucket,
        data_bucket: s3.Bucket,
        kms_key: Optional[kms.Key] = None,
        external_account_id: Optional[str] = None,
    ) -> None:
        """Configure audit bucket to receive S3 access logs from current and optionally external accounts.

        The audit bucket grants the S3 logging service permission to write access logs.
        This supports multi-account setups where external AWS accounts can deliver their logs here.
        """
        # Get current account ID for scoping the logging service principal
        current_account = Stack.of(audit_bucket).account

        # Allow S3 logging service from current account to write access logs
        audit_bucket.add_to_resource_policy(
            iam.PolicyStatement(
                sid="AllowS3LoggingService",
                effect=iam.Effect.ALLOW,
                principals=[iam.ServicePrincipal("logging.s3.amazonaws.com")],
                actions=["s3:GetBucketAcl", "s3:PutObject"],
                resources=[
                    audit_bucket.bucket_arn,
                    audit_bucket.arn_for_objects("logs/access/*"),
                ],
                conditions={
                    "StringEquals": {
                        "aws:SourceAccount": current_account,
                    }
                },
            )
        )

        # If configured for multi-account setup, allow external account's S3 logging service
        if external_account_id:
            audit_bucket.add_to_resource_policy(
                iam.PolicyStatement(
                    sid="AllowExternalAccountS3Logging",
                    effect=iam.Effect.ALLOW,
                    principals=[iam.ServicePrincipal("logging.s3.amazonaws.com")],
                    actions=["s3:GetBucketAcl", "s3:PutObject"],
                    resources=[
                        audit_bucket.bucket_arn,
                        audit_bucket.arn_for_objects("logs/access/*"),
                    ],
                    conditions={
                        "StringEquals": {
                            "aws:SourceAccount": external_account_id,
                        }
                    },
                )
            )

        # Enforce encryption and TLS for all audit bucket operations
        S3PolicyManager.add_encryption_enforcement(audit_bucket, kms_key)
        S3PolicyManager.add_ssl_enforcement(audit_bucket)

    @staticmethod
    def add_deny_delete_policy(bucket: s3.Bucket) -> None:
        """Deny all object deletion from the audit bucket to protect the audit trail."""
        bucket.add_to_resource_policy(
            iam.PolicyStatement(
                sid="AuditTrailDeleteProtection",
                effect=iam.Effect.DENY,
                principals=[iam.AnyPrincipal()],
                actions=[
                    "s3:DeleteObject",
                    "s3:DeleteObjectVersion",
                ],
                resources=[bucket.arn_for_objects("*")],
            )
        )

    @staticmethod
    def deny_public_access(bucket: s3.Bucket) -> None:
        """Explicitly deny public read access as an additional security layer.

        This provides defense-in-depth alongside BlockPublicAccess settings.
        Prevents accidental exposure if bucket policies or ACLs are modified.
        """
        # Deny all public read operations from unauthenticated principals
        # BlockPublicAccess already blocks at account level, but this explicit policy adds extra protection
        bucket.add_to_resource_policy(
            iam.PolicyStatement(
                sid="DenyPublicRead",
                effect=iam.Effect.DENY,
                principals=[iam.PublicPrincipal()],
                actions=["s3:GetObject", "s3:GetObjectVersion", "s3:ListBucket"],
                resources=[
                    bucket.bucket_arn,
                    bucket.arn_for_objects("*"),
                ],
            )
        )

    @staticmethod
    def configure_bucket_policies(
        bucket: s3.Bucket,
        props: SecureS3BucketProps,
        kms_key: Optional[kms.Key] = None,
        is_audit_bucket: bool = False,
    ) -> None:
        """Apply all bucket policies based on compliance configuration.

        Configures public access blocking, encryption enforcement, SSL/TLS enforcement,
        and deletion protection (for audit buckets).
        """
        # Block public access: BlockPublicAccess is already set at bucket construction,
        # add explicit DENY policy as additional defense-in-depth layer
        if props.compliance.block_all_public_access:
            S3PolicyManager.deny_public_access(bucket)

        # Enforce KMS encryption for all uploads
        if props.compliance.enforce_encryption:
            S3PolicyManager.add_encryption_enforcement(bucket, kms_key)

        # Enforce HTTPS-only access (deny HTTP)
        if props.compliance.enforce_ssl_only:
            S3PolicyManager.add_ssl_enforcement(bucket)

        # Protect audit bucket from accidental deletion of logs
        if is_audit_bucket:
            S3PolicyManager.add_deny_delete_policy(bucket)
