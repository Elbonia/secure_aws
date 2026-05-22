from aws_cdk import (
    Duration,
    aws_s3 as s3,
)
from typing import List
from .props import LifecycleProps


class LifecycleManager:
    """Manages S3 lifecycle policies for retention and data tiering."""

    @staticmethod
    def create_lifecycle_rules(props: LifecycleProps) -> List[s3.LifecycleRule]:
        """Create lifecycle rules based on configuration."""
        rules = []

        # Primary retention rule - expire objects after retention period
        rules.append(
            s3.LifecycleRule(
                id="ExpireObjects",
                expiration=Duration.days(props.retention_days),
                enabled=True,
            )
        )

        # Intelligent Tiering: automatically moves objects between access tiers based on access patterns
        # (applies immediately: 0 days)
        if props.enable_intelligent_tiering:
            rules.append(
                s3.LifecycleRule(
                    id="IntelligentTiering",
                    transitions=[
                        s3.Transition(
                            storage_class=s3.StorageClass.INTELLIGENT_TIERING,
                            transition_after=Duration.days(0),
                        )
                    ],
                    enabled=True,
                )
            )

        # Glacier transition: move objects to standard Glacier storage after specified days
        # Note: Deep Archive transitions are handled separately in a distinct rule below
        if props.glacier_transition_enabled:
            rules.append(
                s3.LifecycleRule(
                    id="GlacierTransition",
                    transitions=[
                        s3.Transition(
                            storage_class=s3.StorageClass.GLACIER,
                            transition_after=Duration.days(
                                props.glacier_transition_days
                            ),
                        )
                    ],
                    enabled=True,
                )
            )

        # Deep archive transition (if both enabled)
        if (
            props.deep_archive_transition_enabled
            and props.glacier_transition_enabled
        ):
            rules.append(
                s3.LifecycleRule(
                    id="DeepArchiveTransition",
                    transitions=[
                        s3.Transition(
                            storage_class=s3.StorageClass.DEEP_ARCHIVE,
                            transition_after=Duration.days(
                                props.deep_archive_transition_days
                            ),
                        )
                    ],
                    enabled=True,
                )
            )

        # Noncurrent version expiration: delete old object versions to save storage cost
        # Only applies when versioning is enabled
        if props.enable_noncurrent_version_expiration:
            rules.append(
                s3.LifecycleRule(
                    id="ExpireNoncurrentVersions",
                    noncurrent_version_expiration=Duration.days(
                        props.noncurrent_version_expiration_days
                    ),
                    enabled=True,
                )
            )

        # Clean up incomplete multipart uploads after 7 days (prevents orphaned chunks from consuming storage)
        rules.append(
            s3.LifecycleRule(
                id="CleanupIncompleteMultipartUploads",
                abort_incomplete_multipart_upload=Duration.days(7),
                enabled=True,
            )
        )

        return rules

    @staticmethod
    def create_audit_bucket_lifecycle_rules(
        retention_days: int = 90,
    ) -> List[s3.LifecycleRule]:
        """Create lifecycle rules for audit bucket logs.

        Audit logs are typically accessed infrequently but must be retained for compliance.
        Glacier transition happens at 30 days if retention > 90 days (respects Glacier's 90-day minimum).
        """
        rules = [
            s3.LifecycleRule(
                id="ExpireAuditLogs",
                expiration=Duration.days(retention_days),
                enabled=True,
            ),
        ]
        # Only transition to Glacier when retention is long enough to avoid Glacier's 90-day minimum charge.
        # Moving logs to Glacier after 30 days saves cost for longer retention periods.
        if retention_days > 90:
            rules.append(
                s3.LifecycleRule(
                    id="ArchiveAuditLogs",
                    transitions=[
                        s3.Transition(
                            storage_class=s3.StorageClass.GLACIER,
                            transition_after=Duration.days(30),
                        )
                    ],
                    enabled=True,
                )
            )
        return rules
