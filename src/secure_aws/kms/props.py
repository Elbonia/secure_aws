from dataclasses import dataclass
from typing import Optional
from aws_cdk import RemovalPolicy


@dataclass
class SecureKmsKeyProps:
    """Configuration for a standalone secure KMS key."""

    # Alias name without the "alias/" prefix, e.g. "s3/my-bucket" or "my-service/prod"
    alias: str

    rotation_enabled: bool = True
    rotation_period_days: int = 90
    description: Optional[str] = None
    removal_policy: RemovalPolicy = RemovalPolicy.DESTROY
