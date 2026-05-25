#!/usr/bin/env python3
import os
import aws_cdk as cdk

# S3 construct and its own props
from secure_aws.s3 import SecureAuditedS3Bucket, SecureS3BucketProps, MonitoringProps

# KMS config lives in the kms module — imported directly from there, not via s3
from secure_aws.kms import KMSProps

app = cdk.App()
stack = cdk.Stack(
    app,
    "secure-aws-test",
    env=cdk.Environment(
        account=os.environ["CDK_DEFAULT_ACCOUNT"],
        region=os.environ["CDK_DEFAULT_REGION"],
    ),
)

SecureAuditedS3Bucket(
    stack,
    "TestBucket",
    SecureS3BucketProps(
        bucket_name=f"secure-aws-test-{os.environ['CDK_DEFAULT_ACCOUNT']}",
        environment="test",
        project_name="secure-aws",
        audit_bucket_name=f"secure-aws-test-{os.environ['CDK_DEFAULT_ACCOUNT']}-audit",
        kms=KMSProps(
            enable_kms=True,
            key_rotation_enabled=True,
            key_rotation_period_days=90,
        ),
        monitoring=MonitoringProps(
            enable_cloudwatch_alarms=False,
            enable_sns_alerts=False,
        ),
    ),
)

app.synth()
