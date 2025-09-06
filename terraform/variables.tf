variable "aws_region" {
  description = "AWS region for resources"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
  default     = "dev"
}

variable "project_name" {
  description = "Name of the project"
  type        = string
  default     = "secure-upload"
}

variable "owner" {
  description = "Owner of the resources"
  type        = string
  default     = "devops-team"
}

variable "cost_center" {
  description = "Cost center for billing"
  type        = string
  default     = "engineering"
}

variable "kms_deletion_window" {
  description = "KMS key deletion window in days"
  type        = number
  default     = 7
}

variable "log_retention_days" {
  description = "CloudWatch log retention in days"
  type        = number
  default     = 30
}

variable "multipart_threshold" {
  description = "Multipart upload threshold in MB"
  type        = number
  default     = 100
}

variable "multipart_chunksize" {
  description = "Multipart upload chunk size in MB"
  type        = number
  default     = 8
}

variable "max_file_size_gb" {
  description = "Maximum allowed file size in GB"
  type        = number
  default     = 5
}

variable "allowed_file_types" {
  description = "Allowed file types for upload"
  type        = list(string)
  default = [
    ".zip",
    ".tar",
    ".gz",
    ".pdf",
    ".doc",
    ".docx",
    ".xls",
    ".xlsx",
    ".ppt",
    ".pptx",
    ".txt",
    ".csv",
    ".json",
    ".xml",
    ".yml",
    ".yaml"
  ]
}

variable "enable_cloudtrail" {
  description = "Enable CloudTrail logging"
  type        = bool
  default     = true
}

variable "enable_config" {
  description = "Enable AWS Config compliance monitoring"
  type        = bool
  default     = true
}

variable "enable_mfa" {
  description = "Enable MFA requirement for IAM roles"
  type        = bool
  default     = true
}

variable "sns_email_endpoint" {
  description = "Email endpoint for SNS security alerts"
  type        = string
  default     = ""
}

variable "backup_retention_days" {
  description = "Number of days to retain backups"
  type        = number
  default     = 90
}

variable "enable_transfer_acceleration" {
  description = "Enable S3 Transfer Acceleration"
  type        = bool
  default     = false
}

variable "enable_cross_region_replication" {
  description = "Enable cross-region replication"
  type        = bool
  default     = false
}

variable "replica_region" {
  description = "Region for cross-region replication"
  type        = string
  default     = "us-west-2"
}

variable "vpc_id" {
  description = "VPC ID for VPC endpoints (optional)"
  type        = string
  default     = ""
}

variable "subnet_ids" {
  description = "Subnet IDs for VPC endpoints (optional)"
  type        = list(string)
  default     = []
}

variable "enable_vpc_endpoints" {
  description = "Enable VPC endpoints for S3 and KMS"
  type        = bool
  default     = false
}
