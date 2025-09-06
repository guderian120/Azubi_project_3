output "s3_bucket_name" {
  description = "Name of the secure uploads S3 bucket"
  value       = aws_s3_bucket.secure_uploads.bucket
}

output "s3_bucket_arn" {
  description = "ARN of the secure uploads S3 bucket"
  value       = aws_s3_bucket.secure_uploads.arn
}

output "s3_bucket_domain_name" {
  description = "Domain name of the secure uploads S3 bucket"
  value       = aws_s3_bucket.secure_uploads.bucket_domain_name
}

output "kms_key_id" {
  description = "ID of the KMS key used for encryption"
  value       = aws_kms_key.s3_encryption.key_id
}

output "kms_key_arn" {
  description = "ARN of the KMS key used for encryption"
  value       = aws_kms_key.s3_encryption.arn
}

output "kms_alias_name" {
  description = "Alias name of the KMS key"
  value       = aws_kms_alias.s3_encryption.name
}

output "upload_role_arn" {
  description = "ARN of the upload IAM role"
  value       = aws_iam_role.upload_role.arn
}

output "admin_role_arn" {
  description = "ARN of the admin IAM role"
  value       = aws_iam_role.admin_role.arn
}

output "readonly_role_arn" {
  description = "ARN of the readonly IAM role"
  value       = aws_iam_role.readonly_role.arn
}

output "cloudtrail_name" {
  description = "Name of the CloudTrail"
  value       = aws_cloudtrail.main.name
}

output "cloudtrail_arn" {
  description = "ARN of the CloudTrail"
  value       = aws_cloudtrail.main.arn
}

output "sns_topic_arn" {
  description = "ARN of the SNS topic for security alerts"
  value       = aws_sns_topic.security_alerts.arn
}

output "cloudwatch_log_group_name" {
  description = "Name of the CloudWatch log group"
  value       = aws_cloudwatch_log_group.app_logs.name
}

output "access_logs_bucket_name" {
  description = "Name of the access logs S3 bucket"
  value       = aws_s3_bucket.access_logs.bucket
}

output "config_bucket_name" {
  description = "Name of the AWS Config S3 bucket"
  value       = aws_s3_bucket.config_bucket.bucket
}

output "cloudtrail_logs_bucket_name" {
  description = "Name of the CloudTrail logs S3 bucket"
  value       = aws_s3_bucket.cloudtrail_logs.bucket
}

output "instance_profile_name" {
  description = "Name of the IAM instance profile"
  value       = aws_iam_instance_profile.upload_instance_profile.name
}

output "region" {
  description = "AWS region"
  value       = data.aws_region.current.name
}

output "account_id" {
  description = "AWS account ID"
  value       = data.aws_caller_identity.current.account_id
}

# Security and compliance outputs
output "security_config" {
  description = "Security configuration summary"
  value = {
    encryption_enabled    = true
    mfa_required         = var.enable_mfa
    cloudtrail_enabled   = var.enable_cloudtrail
    config_enabled       = var.enable_config
    ssl_enforced         = true
    public_access_blocked = true
  }
}

output "bucket_policies" {
  description = "Summary of bucket security policies"
  value = {
    ssl_requests_only           = true
    encrypted_uploads_only      = true
    public_access_blocked       = true
    access_logging_enabled      = true
    versioning_enabled          = true
    lifecycle_configured        = true
    multipart_cleanup_enabled   = true
  }
}

output "monitoring_config" {
  description = "Monitoring configuration summary"
  value = {
    cloudtrail_enabled          = var.enable_cloudtrail
    access_logs_enabled         = true
    cloudwatch_alarms_enabled   = true
    sns_alerts_enabled          = true
    config_rules_enabled        = var.enable_config
    log_retention_days          = var.log_retention_days
  }
}

# Connection details for applications
output "connection_config" {
  description = "Configuration for connecting applications"
  value = {
    bucket_name    = aws_s3_bucket.secure_uploads.bucket
    kms_key_id     = aws_kms_key.s3_encryption.key_id
    region         = data.aws_region.current.name
    upload_role    = aws_iam_role.upload_role.arn
    admin_role     = aws_iam_role.admin_role.arn
    readonly_role  = aws_iam_role.readonly_role.arn
  }
  sensitive = false
}
