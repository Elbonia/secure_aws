from dataclasses import dataclass, field
from typing import Optional, List, Dict

from ..props import ComplianceMode  # noqa: F401 — re-exported for callers who import from secure_aws.s3
from ..kms.props import KMSProps    # noqa: F401 — re-exported for callers who import from secure_aws.s3


@dataclass
class ReplicationProps:
    """Cross-region replication configuration."""
    enable_replication: bool = False
    destination_region: Optional[str] = None
    destination_bucket_name: Optional[str] = None
    replication_role_name: Optional[str] = None
    delete_marker_replication: bool = True


@dataclass
class LifecycleProps:
    """Lifecycle and retention configuration."""
    retention_days: int = 30
    enable_intelligent_tiering: bool = False
    glacier_transition_enabled: bool = False
    glacier_transition_days: int = 90
    deep_archive_transition_enabled: bool = False
    deep_archive_transition_days: int = 180
    enable_noncurrent_version_expiration: bool = True
    noncurrent_version_expiration_days: int = 7


@dataclass
class MonitoringProps:
    """CloudWatch and logging configuration."""
    enable_access_logging: bool = True
    enable_request_metrics: bool = True
    enable_cloudwatch_alarms: bool = True
    enable_sns_alerts: bool = True
    sns_topic_name: Optional[str] = None
    log_prefix: str = "logs/access/"
    audit_bucket_log_prefix: str = "logs/audit-bucket/"
    cloudwatch_log_retention_days: int = 90
    enable_event_notifications: bool = True

    # Alarm thresholds (production-ready defaults)
    alarm_4xx_threshold: int = 10
    alarm_5xx_threshold: int = 5
    alarm_bucket_size_threshold_gb: int = 1000
    alarm_evaluation_periods: int = 1


@dataclass
class ComplianceProps:
    """HIPAA and CIS compliance configuration."""
    enforce_compliance: bool = True
    compliance_mode: ComplianceMode = ComplianceMode.STRICT
    enforce_versioning: bool = True
    enforce_encryption: bool = True
    enforce_ssl_only: bool = True
    block_all_public_access: bool = True
    enable_object_lock: bool = False
    object_lock_mode: Optional[str] = None
    object_lock_retention_days: Optional[int] = None


@dataclass
class VPCAccessProps:
    """VPC endpoint and network access configuration."""
    restrict_to_vpc: bool = False
    allowed_vpc_ids: List[str] = field(default_factory=list)
    allowed_vpc_endpoints: List[str] = field(default_factory=list)
    allow_cross_account_ingestion: bool = False
    cross_account_principals: List[str] = field(default_factory=list)


@dataclass
class SecureS3BucketProps:
    """Complete configuration for SecureAuditedS3Bucket construct."""
    bucket_name: str
    environment: str
    project_name: str

    # Compliance
    compliance: ComplianceProps = field(default_factory=ComplianceProps)

    # KMS
    kms: KMSProps = field(default_factory=KMSProps)

    # Replication
    replication: ReplicationProps = field(default_factory=ReplicationProps)

    # Lifecycle
    lifecycle: LifecycleProps = field(default_factory=LifecycleProps)

    # Monitoring
    monitoring: MonitoringProps = field(default_factory=MonitoringProps)

    # VPC Access Control
    vpc_access: VPCAccessProps = field(default_factory=VPCAccessProps)

    # Audit bucket
    audit_bucket_name: str = ""
    external_audit_account_id: Optional[str] = None

    # Optional features (strict by default)
    enable_versioning: bool = True

    # Tags
    tags: Dict[str, str] = field(default_factory=dict)

    # Removal policy — DESTROY removes empty buckets on teardown, but fails if objects exist
    removal_policy: str = "DESTROY"
