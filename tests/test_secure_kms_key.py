"""
Verify SecureKmsKey works as a standalone construct with no S3 dependency.

These tests import exclusively from secure_aws.kms to confirm the module is
self-contained and usable outside of any service construct.
"""

import aws_cdk as cdk
from aws_cdk import assertions, RemovalPolicy

from secure_aws.kms import SecureKmsKey, SecureKmsKeyProps


def make_key_template(props: SecureKmsKeyProps) -> assertions.Template:
    app = cdk.App()
    stack = cdk.Stack(app, "TestStack", env=cdk.Environment(account="123456789012", region="us-east-1"))
    SecureKmsKey(stack, "TestKey", props)
    return assertions.Template.from_stack(stack)


def default_props(**overrides) -> SecureKmsKeyProps:
    return SecureKmsKeyProps(alias="test/my-key", **overrides)


class TestSecureKmsKeyCreation:
    """Key and alias are created with the correct configuration."""

    def test_kms_key_is_created(self):
        template = make_key_template(default_props())
        template.resource_count_is("AWS::KMS::Key", 1)

    def test_alias_is_created(self):
        template = make_key_template(default_props())
        template.has_resource_properties("AWS::KMS::Alias", {
            "AliasName": "alias/test/my-key",
        })

    def test_rotation_enabled_by_default(self):
        template = make_key_template(default_props())
        template.has_resource_properties("AWS::KMS::Key", {
            "EnableKeyRotation": True,
        })

    def test_rotation_disabled(self):
        template = make_key_template(default_props(rotation_enabled=False))
        template.has_resource_properties("AWS::KMS::Key", {
            "EnableKeyRotation": False,
        })

    def test_description_defaults_to_alias(self):
        template = make_key_template(default_props())
        template.has_resource_properties("AWS::KMS::Key", {
            "Description": "Secure KMS key: alias/test/my-key",
        })

    def test_custom_description(self):
        template = make_key_template(default_props(description="My custom key"))
        template.has_resource_properties("AWS::KMS::Key", {
            "Description": "My custom key",
        })


class TestSecureKmsKeyRemovalPolicy:
    """Removal policy is applied correctly to the underlying key."""

    def test_destroy_by_default(self):
        template = make_key_template(default_props())
        keys = template.find_resources("AWS::KMS::Key", {"DeletionPolicy": "Delete"})
        assert len(keys) == 1, "Key should have DeletionPolicy: Delete by default"

    def test_retain_policy(self):
        template = make_key_template(default_props(removal_policy=RemovalPolicy.RETAIN))
        keys = template.find_resources("AWS::KMS::Key", {"DeletionPolicy": "Retain"})
        assert len(keys) == 1, "Key should have DeletionPolicy: Retain"


class TestSecureKmsKeyGrants:
    """grant_* methods add the correct key policy statements."""

    def test_grant_s3_bucket_adds_policy(self):
        app = cdk.App()
        stack = cdk.Stack(app, "TestStack", env=cdk.Environment(account="123456789012", region="us-east-1"))
        key = SecureKmsKey(stack, "TestKey", default_props())
        key.grant_s3_bucket("my-test-bucket")
        template = assertions.Template.from_stack(stack)

        template.has_resource_properties("AWS::KMS::Key", {
            "KeyPolicy": assertions.Match.object_like({
                "Statement": assertions.Match.array_with([
                    assertions.Match.object_like({
                        "Sid": "AllowS3ForBucketmytestbucket",
                        "Principal": {"Service": "s3.amazonaws.com"},
                    })
                ])
            })
        })

    def test_grant_cloudwatch_logs_adds_policy(self):
        app = cdk.App()
        stack = cdk.Stack(app, "TestStack", env=cdk.Environment(account="123456789012", region="us-east-1"))
        key = SecureKmsKey(stack, "TestKey", default_props())
        key.grant_cloudwatch_logs(["/aws/lambda/my-function"])
        template = assertions.Template.from_stack(stack)

        template.has_resource_properties("AWS::KMS::Key", {
            "KeyPolicy": assertions.Match.object_like({
                "Statement": assertions.Match.array_with([
                    assertions.Match.object_like({
                        "Sid": "AllowCloudWatchLogs",
                        "Principal": {"Service": "logs.us-east-1.amazonaws.com"},
                    })
                ])
            })
        })
