# CloudTrail for audit logging
resource "aws_s3_bucket" "cloudtrail_logs" {
  bucket = "${local.common_name}-cloudtrail-logs"

  tags = {
    Name = "${local.common_name}-cloudtrail-logs"
  }
}

resource "aws_s3_bucket_public_access_block" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AWSCloudTrailAclCheck"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:GetBucketAcl"
        Resource = aws_s3_bucket.cloudtrail_logs.arn
        Condition = {
          StringEquals = {
            "aws:SourceArn" = "arn:aws:cloudtrail:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:trail/${local.common_name}-cloudtrail"
          }
        }
      },
      {
        Sid    = "AWSCloudTrailWrite"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.cloudtrail_logs.arn}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
            "aws:SourceArn" = "arn:aws:cloudtrail:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:trail/${local.common_name}-cloudtrail"
          }
        }
      }
    ]
  })
}

# CloudTrail
resource "aws_cloudtrail" "main" {
  name           = "${local.common_name}-cloudtrail"
  s3_bucket_name = aws_s3_bucket.cloudtrail_logs.bucket
  s3_key_prefix  = "cloudtrail-logs"

  include_global_service_events = true
  is_multi_region_trail         = true
  enable_logging                = true

  event_selector {
    read_write_type                 = "All"
    include_management_events       = true

    data_resource {
      type   = "AWS::S3::Object"
      values = ["${aws_s3_bucket.secure_uploads.arn}/*"]
    }

    data_resource {
      type   = "AWS::S3::Bucket"
      values = [aws_s3_bucket.secure_uploads.arn]
    }
  }

  tags = {
    Name = "${local.common_name}-cloudtrail"
  }

  depends_on = [aws_s3_bucket_policy.cloudtrail_logs]
}

# SNS Topic for security alerts
resource "aws_sns_topic" "security_alerts" {
  name = "${local.common_name}-security-alerts"

  tags = {
    Name = "${local.common_name}-security-alerts"
  }
}

resource "aws_sns_topic_policy" "security_alerts" {
  arn = aws_sns_topic.security_alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "CloudWatchAlarmsPolicy"
        Effect = "Allow"
        Principal = {
          Service = "cloudwatch.amazonaws.com"
        }
        Action   = "sns:Publish"
        Resource = aws_sns_topic.security_alerts.arn
      }
    ]
  })
}

# CloudWatch Log Group for application logs
resource "aws_cloudwatch_log_group" "app_logs" {
  name              = "/aws/application/${local.common_name}"
  retention_in_days = var.log_retention_days

  tags = {
    Name = "${local.common_name}-app-logs"
  }
}

# CloudWatch Alarms for security monitoring
resource "aws_cloudwatch_metric_alarm" "unauthorized_api_calls" {
  alarm_name          = "${local.common_name}-unauthorized-api-calls"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "UnauthorizedAPICalls"
  namespace           = "CloudTrail"
  period              = "300"
  statistic           = "Sum"
  threshold           = "5"
  alarm_description   = "This metric monitors unauthorized API calls"
  alarm_actions       = [aws_sns_topic.security_alerts.arn]

  tags = {
    Name = "${local.common_name}-unauthorized-api-calls"
  }
}

resource "aws_cloudwatch_metric_alarm" "s3_bucket_policy_changes" {
  alarm_name          = "${local.common_name}-s3-bucket-policy-changes"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "S3BucketPolicyChanges"
  namespace           = "CloudTrail"
  period              = "300"
  statistic           = "Sum"
  threshold           = "0"
  alarm_description   = "This metric monitors S3 bucket policy changes"
  alarm_actions       = [aws_sns_topic.security_alerts.arn]

  tags = {
    Name = "${local.common_name}-s3-bucket-policy-changes"
  }
}

# CloudWatch Log Metric Filters
resource "aws_cloudwatch_log_metric_filter" "unauthorized_api_calls" {
  name           = "${local.common_name}-unauthorized-api-calls-filter"
  log_group_name = aws_cloudwatch_log_group.app_logs.name
  pattern        = "[version, account, time, region, source, account, time, region, source, \"ERROR\", request_id=\"*\", errorCode=\"*UnauthorizedOperation*\" || errorCode=\"*AccessDenied*\"]"

  metric_transformation {
    name      = "UnauthorizedAPICalls"
    namespace = "CloudTrail"
    value     = "1"
  }
}

resource "aws_cloudwatch_log_metric_filter" "s3_bucket_policy_changes" {
  name           = "${local.common_name}-s3-policy-changes-filter"
  log_group_name = aws_cloudwatch_log_group.app_logs.name
  pattern        = "[version, account, time, region, source, account, time, region, source, eventName=\"PutBucketPolicy\" || eventName=\"DeleteBucketPolicy\" || eventName=\"PutBucketAcl\" || eventName=\"PutObjectAcl\"]"

  metric_transformation {
    name      = "S3BucketPolicyChanges"
    namespace = "CloudTrail"
    value     = "1"
  }
}

# AWS Config for compliance monitoring
resource "aws_config_configuration_recorder" "main" {
  name     = "${local.common_name}-config-recorder"
  role_arn = aws_iam_role.config_role.arn

  recording_group {
    all_supported                 = true
    include_global_resource_types = true
  }

  depends_on = [aws_config_delivery_channel.main]
}

resource "aws_config_delivery_channel" "main" {
  name           = "${local.common_name}-config-delivery-channel"
  s3_bucket_name = aws_s3_bucket.config_bucket.bucket

  snapshot_delivery_properties {
    delivery_frequency = "TwentyFour_Hours"
  }
}

resource "aws_s3_bucket" "config_bucket" {
  bucket = "${local.common_name}-config-bucket"

  tags = {
    Name = "${local.common_name}-config-bucket"
  }
}

resource "aws_s3_bucket_public_access_block" "config_bucket" {
  bucket = aws_s3_bucket.config_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# IAM Role for AWS Config
resource "aws_iam_role" "config_role" {
  name = "${local.common_name}-config-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "config.amazonaws.com"
        }
      }
    ]
  })

  tags = {
    Name = "${local.common_name}-config-role"
  }
}

resource "aws_iam_role_policy_attachment" "config_role_policy" {
  role       = aws_iam_role.config_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/ConfigRole"
}

resource "aws_iam_role_policy" "config_s3_policy" {
  name = "${local.common_name}-config-s3-policy"
  role = aws_iam_role.config_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetBucketAcl",
          "s3:GetBucketLocation",
          "s3:ListBucket"
        ]
        Resource = aws_s3_bucket.config_bucket.arn
      },
      {
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:GetObject"
        ]
        Resource = "${aws_s3_bucket.config_bucket.arn}/*"
      }
    ]
  })
}

# Config Rules for compliance
resource "aws_config_config_rule" "s3_bucket_ssl_requests_only" {
  name = "${local.common_name}-s3-ssl-requests-only"

  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_SSL_REQUESTS_ONLY"
  }

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_config_rule" "s3_bucket_server_side_encryption_enabled" {
  name = "${local.common_name}-s3-encryption-enabled"

  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_config_rule" "s3_bucket_public_read_prohibited" {
  name = "${local.common_name}-s3-public-read-prohibited"

  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_PUBLIC_READ_PROHIBITED"
  }

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_config_rule" "s3_bucket_public_write_prohibited" {
  name = "${local.common_name}-s3-public-write-prohibited"

  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_PUBLIC_WRITE_PROHIBITED"
  }

  depends_on = [aws_config_configuration_recorder.main]
}
