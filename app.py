#!/usr/bin/env python3
import os
import aws_cdk as cdk
from secure_aws.s3 import SecureAuditedS3Bucket, SecureS3BucketProps, MonitoringProps

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
        monitoring=MonitoringProps(
            enable_cloudwatch_alarms=False,
            enable_sns_alerts=False,
        ),
    ),
)

app.synth()
