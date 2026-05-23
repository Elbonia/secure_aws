from dataclasses import dataclass
from typing import Optional
from aws_cdk import RemovalPolicy


@dataclass
class SecureKmsKeyProps:
    """Low-level construct config for SecureKmsKey.

    Used when creating a key directly. Higher-level constructs (e.g. S3, CloudTrail)
    accept KMSProps instead, which adds service-level toggles on top of these settings.
    """

    # Alias name without the "alias/" prefix, e.g. "s3/my-bucket" or "my-service/prod"
    alias: str

    rotation_enabled: bool = True
    rotation_period_days: int = 90
    description: Optional[str] = None
    removal_policy: RemovalPolicy = RemovalPolicy.DESTROY


@dataclass
class KMSProps:
    """KMS encryption configuration for service-level constructs.

    Controls whether KMS is used at all and how the key is configured.
    Consumed by S3, CloudTrail, and other constructs that optionally encrypt
    with a customer-managed key.
    """

    enable_kms: bool = True
    key_rotation_enabled: bool = True
    key_rotation_period_days: int = 90
    key_alias_prefix: Optional[str] = None
