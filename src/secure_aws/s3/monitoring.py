from constructs import Construct
from aws_cdk import (
    Duration,
    RemovalPolicy,
    aws_s3 as s3,
    aws_cloudwatch as cloudwatch,
    aws_sns as sns,
    aws_logs as logs,
    aws_kms as kms,
    aws_cloudtrail as cloudtrail,
)
from typing import Optional
from .props import MonitoringProps


class MonitoringManager:
    """Manages CloudWatch, SNS, and logging for S3 buckets."""

    @staticmethod
    def create_sns_topic(
        scope: Construct,
        id: str,
        topic_name: Optional[str] = None,
        kms_key: Optional[kms.Key] = None,
    ) -> sns.Topic:
        """Create SNS topic for alerts."""
        topic_name = topic_name or f"s3-security-alerts-{id}"

        topic = sns.Topic(
            scope,
            id,
            display_name="S3 Security Alerts",
            topic_name=topic_name,
            master_key=kms_key,
        )

        return topic

    @staticmethod
    def create_cloudwatch_alarms(
        scope: Construct,
        bucket: s3.Bucket,
        id_prefix: str,
        sns_topic: Optional[sns.Topic] = None,
        props: Optional["MonitoringProps"] = None,
    ) -> dict:
        """Create CloudWatch alarms for bucket monitoring."""
        if props is None:
            props = MonitoringProps()

        alarms = {}

        # Object count alarm - detect unexpected changes
        alarms["object_count"] = bucket.metrics.object_count().create_alarm(
            scope,
            f"{id_prefix}-object-count-alarm",
            threshold=0,
            evaluation_periods=props.alarm_evaluation_periods,
            alarm_description="Alert if object count reaches zero unexpectedly",
        )

        # Storage size alarm
        alarms["bucket_size"] = bucket.metrics.bucket_size_bytes().create_alarm(
            scope,
            f"{id_prefix}-bucket-size-alarm",
            threshold=props.alarm_bucket_size_threshold_gb * 1024 * 1024 * 1024,
            evaluation_periods=props.alarm_evaluation_periods,
            alarm_description=f"Alert if bucket size exceeds {props.alarm_bucket_size_threshold_gb}GB",
        )

        # 4xx errors alarm (access denied, bad requests)
        alarms["4xx_errors"] = cloudwatch.Metric(
            namespace="AWS/S3",
            metric_name="4xxErrors",
            statistic="Sum",
            period=Duration.minutes(5),
            dimensions_map={"BucketName": bucket.bucket_name},
        ).create_alarm(
            scope,
            f"{id_prefix}-4xx-errors-alarm",
            threshold=props.alarm_4xx_threshold,
            evaluation_periods=props.alarm_evaluation_periods,
            alarm_description=f"Alert on 4xx errors (access denied, etc) - threshold: {props.alarm_4xx_threshold}",
        )

        # 5xx errors alarm (server errors)
        alarms["5xx_errors"] = cloudwatch.Metric(
            namespace="AWS/S3",
            metric_name="5xxErrors",
            statistic="Sum",
            period=Duration.minutes(5),
            dimensions_map={"BucketName": bucket.bucket_name},
        ).create_alarm(
            scope,
            f"{id_prefix}-5xx-errors-alarm",
            threshold=props.alarm_5xx_threshold,
            evaluation_periods=props.alarm_evaluation_periods,
            alarm_description=f"Alert on 5xx errors (server issues) - threshold: {props.alarm_5xx_threshold}",
        )

        # Add SNS notification if topic provided
        if sns_topic:
            for alarm in alarms.values():
                alarm.add_alarm_action(cloudwatch.SnsAction(sns_topic))

        return alarms

    @staticmethod
    def setup_bucket_logging(
        scope: Construct,
        bucket: s3.Bucket,
        audit_bucket: s3.Bucket,
        props: MonitoringProps,
        kms_key: Optional[kms.Key] = None,
    ) -> None:
        """Configure bucket logging: access logs, CloudWatch metrics, and optional alarms."""
        # Create request count alarm if both metrics and alarms are enabled
        if props.enable_request_metrics and props.enable_cloudwatch_alarms:
            bucket.metrics.all_requests_count().create_alarm(
                scope,
                f"{bucket.bucket_name}-requests-alarm",
                threshold=0,
                evaluation_periods=1,
            )

        # Create CloudWatch Log Group for S3 access logs with configured retention
        logs.LogGroup(
            scope,
            f"{bucket.bucket_name}-log-group",
            log_group_name=f"/aws/s3/{bucket.bucket_name}",
            retention=logs.RetentionDays(props.cloudwatch_log_retention_days),
            encryption_key=kms_key if kms_key else None,
            removal_policy=RemovalPolicy.RETAIN,
        )
        # Additional alarms (public exposure detection, etc.) are created separately in _setup_monitoring

    @staticmethod
    def create_audit_bucket_logging(
        scope: Construct,
        audit_bucket: s3.Bucket,
        props: MonitoringProps,
        kms_key: Optional[kms.Key] = None,
    ) -> None:
        """Configure logging for the audit bucket itself."""
        logs.LogGroup(
            scope,
            f"audit-bucket-log-group",
            log_group_name=f"/aws/s3/audit/{audit_bucket.bucket_name}",
            retention=logs.RetentionDays(props.cloudwatch_log_retention_days),
            encryption_key=kms_key if kms_key else None,
            removal_policy=RemovalPolicy.RETAIN,
        )

        if props.enable_request_metrics and props.enable_cloudwatch_alarms:
            audit_bucket.metrics.all_requests_count().create_alarm(
                scope,
                f"audit-bucket-requests-alarm",
                threshold=0,
                evaluation_periods=1,
            )

    @staticmethod
    def create_public_exposure_alarms(
        scope: Construct,
        bucket_name: str,
        audit_bucket: s3.Bucket,
        kms_key: Optional[kms.Key] = None,
        sns_topic: Optional[sns.Topic] = None,
    ) -> dict:
        """Create CloudTrail trail with metric filters and alarms for S3 policy/ACL changes.

        This detects attempts to make buckets public by monitoring management events
        like PutBucketPolicy, PutBucketAcl, and PutAccountPublicAccessBlock changes.
        Alarms trigger immediately on suspicious configuration changes.
        """
        log_group = logs.LogGroup(
            scope,
            f"{bucket_name}-trail-log-group",
            log_group_name=f"/aws/cloudtrail/{bucket_name}",
            retention=logs.RetentionDays.ONE_YEAR,
            encryption_key=kms_key if kms_key else None,
            removal_policy=RemovalPolicy.RETAIN,
        )

        # Create CloudTrail trail to log all management events (config changes) to the audit bucket
        trail = cloudtrail.Trail(
            scope,
            f"{bucket_name}-trail",
            bucket=audit_bucket,
            cloud_watch_log_group=log_group,
            s3_key_prefix="cloudtrail",
            send_to_cloud_watch_logs=True,
            include_global_service_events=True,
            is_multi_region_trail=True,
            enable_file_validation=True,
        )
        # Captures management events (PutBucketPolicy, PutBucketAcl, etc.) by default.
        # Data events (GetObject, PutObject) intentionally excluded—not needed for public exposure detection.

        metric_namespace = f"CloudTrailMetrics/{bucket_name}"

        metric_definitions = [
            ("PutBucketPolicy", "$.eventName = PutBucketPolicy", "policy_change",
             f"Alert on bucket policy changes for {bucket_name}"),
            ("PutBucketAcl", "$.eventName = PutBucketAcl", "acl_change",
             f"Alert on ACL changes for {bucket_name}"),
            ("DeleteBucketPolicy", "$.eventName = DeleteBucketPolicy", "policy_delete",
             f"Alert on bucket policy deletion for {bucket_name}"),
            ("PutAccountPublicAccessBlock", "$.eventName = PutAccountPublicAccessBlock",
             "block_public_access_change", f"Alert on BlockPublicAccess changes for {bucket_name}"),
        ]

        alarms = {}
        for metric_name, filter_pattern, alarm_key, description in metric_definitions:
            logs.MetricFilter(
                scope,
                f"{bucket_name}-{metric_name}-filter",
                log_group=log_group,
                metric_namespace=metric_namespace,
                metric_name=metric_name,
                filter_pattern=logs.FilterPattern.literal(filter_pattern),
                metric_value="1",
                default_value=0,
            )

            alarms[alarm_key] = cloudwatch.Alarm(
                scope,
                f"{bucket_name}-{alarm_key}-alarm",
                metric=cloudwatch.Metric(
                    namespace=metric_namespace,
                    metric_name=metric_name,
                    statistic="Sum",
                    period=Duration.minutes(1),
                ),
                threshold=1,
                evaluation_periods=1,
                alarm_description=description,
                treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING,
            )

        if sns_topic:
            for alarm in alarms.values():
                alarm.add_alarm_action(cloudwatch.SnsAction(sns_topic))

        return alarms
