"""
Verify that S3 buckets and their KMS keys are deleted together when a stack is destroyed.

CDK translates RemovalPolicy.DESTROY into DeletionPolicy: Delete on the CloudFormation
resource. These tests assert that policy is present on every bucket and KMS key so that
cdk destroy cleans up the full set of resources without leaving orphaned keys.
"""

import aws_cdk as cdk
import pytest
from aws_cdk import assertions

# S3 construct and S3-specific props
from secure_aws.s3 import SecureAuditedS3Bucket, SecureS3BucketProps, MonitoringProps

# Shared / cross-module props imported from their canonical locations
from secure_aws.kms import KMSProps
from secure_aws.props import ComplianceMode


def make_stack(props: SecureS3BucketProps) -> assertions.Template:
    app = cdk.App()
    stack = cdk.Stack(app, "TestStack")
    SecureAuditedS3Bucket(stack, "TestBucket", props)
    return assertions.Template.from_stack(stack)


def default_props(**overrides) -> SecureS3BucketProps:
    return SecureS3BucketProps(
        bucket_name="test-bucket",
        environment="test",
        project_name="test-project",
        audit_bucket_name="test-bucket-audit",
        **overrides,
    )


class TestDestroyRemovalPolicy:
    """Default removal_policy=DESTROY: all resources should have DeletionPolicy: Delete."""

    def test_data_bucket_has_delete_policy(self):
        template = make_stack(default_props())
        # There should be at least one S3 bucket with DeletionPolicy: Delete
        buckets = template.find_resources(
            "AWS::S3::Bucket",
            {"DeletionPolicy": "Delete"},
        )
        assert len(buckets) >= 1, "Data bucket missing DeletionPolicy: Delete"

    def test_audit_bucket_has_delete_policy(self):
        template = make_stack(default_props())
        buckets = template.find_resources(
            "AWS::S3::Bucket",
            {"DeletionPolicy": "Delete"},
        )
        assert len(buckets) >= 2, "Audit bucket missing DeletionPolicy: Delete"

    def test_data_bucket_kms_key_has_delete_policy(self):
        template = make_stack(default_props())
        keys = template.find_resources(
            "AWS::KMS::Key",
            {"DeletionPolicy": "Delete"},
        )
        assert len(keys) >= 1, "Data bucket KMS key missing DeletionPolicy: Delete"

    def test_audit_bucket_kms_key_has_delete_policy(self):
        template = make_stack(default_props())
        keys = template.find_resources(
            "AWS::KMS::Key",
            {"DeletionPolicy": "Delete"},
        )
        assert len(keys) >= 2, "Audit bucket KMS key missing DeletionPolicy: Delete"

    def test_no_resources_retained(self):
        template = make_stack(default_props())
        retained_buckets = template.find_resources(
            "AWS::S3::Bucket",
            {"DeletionPolicy": "Retain"},
        )
        retained_keys = template.find_resources(
            "AWS::KMS::Key",
            {"DeletionPolicy": "Retain"},
        )
        assert not retained_buckets, f"Unexpected retained buckets: {list(retained_buckets)}"
        assert not retained_keys, f"Unexpected retained KMS keys: {list(retained_keys)}"


class TestRetainRemovalPolicy:
    """Explicit removal_policy=RETAIN: all resources should have DeletionPolicy: Retain."""

    def setup_method(self):
        self.template = make_stack(default_props(removal_policy="RETAIN"))

    def test_buckets_are_retained(self):
        retained = self.template.find_resources(
            "AWS::S3::Bucket",
            {"DeletionPolicy": "Retain"},
        )
        assert len(retained) >= 2, "Expected both buckets to be retained"

    def test_kms_keys_are_retained(self):
        retained = self.template.find_resources(
            "AWS::KMS::Key",
            {"DeletionPolicy": "Retain"},
        )
        assert len(retained) >= 2, "Expected both KMS keys to be retained"

    def test_no_resources_deleted(self):
        deleted_buckets = self.template.find_resources(
            "AWS::S3::Bucket",
            {"DeletionPolicy": "Delete"},
        )
        deleted_keys = self.template.find_resources(
            "AWS::KMS::Key",
            {"DeletionPolicy": "Delete"},
        )
        assert not deleted_buckets, f"Unexpected deletable buckets: {list(deleted_buckets)}"
        assert not deleted_keys, f"Unexpected deletable KMS keys: {list(deleted_keys)}"
