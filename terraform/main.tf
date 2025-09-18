terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
  
  default_tags {
    tags = {
      Environment = var.environment
      Project     = var.project_name
      ManagedBy   = "Terraform"
      Owner       = var.owner
      CostCenter  = var.cost_center
    }
  }
}

# Random suffix for unique resource names
resource "random_string" "suffix" {
  length  = 8
  special = false
  upper   = false
}

locals {
  common_name = "${var.project_name}-${var.environment}-${random_string.suffix.result}"
}

# KMS Key for encryption
resource "aws_kms_key" "s3_encryption" {
  description             = "KMS key for S3 bucket encryption"
  deletion_window_in_days = var.kms_deletion_window
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "Allow use of the key"
        Effect = "Allow"
        Principal = {
          AWS = [
            aws_iam_role.upload_role.arn,
            aws_iam_role.admin_role.arn,
            aws_iam_role.readonly_role.arn
          ]
        }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = "*"
      }
    ]
  })

  tags = {
    Name = "${local.common_name}-kms-key"
  }
}

resource "aws_kms_alias" "s3_encryption" {
  name          = "alias/${local.common_name}-s3-key"
  target_key_id = aws_kms_key.s3_encryption.key_id
}

# S3 Bucket for secure file uploads
resource "aws_s3_bucket" "secure_uploads" {
  bucket = "${local.common_name}-secure-uploads"

  tags = {
    Name = "${local.common_name}-secure-uploads"
  }
}

# S3 Bucket versioning
resource "aws_s3_bucket_versioning" "secure_uploads" {
  bucket = aws_s3_bucket.secure_uploads.id
  versioning_configuration {
    status = "Enabled"
  }
}

# S3 Bucket encryption
resource "aws_s3_bucket_server_side_encryption_configuration" "secure_uploads" {
  bucket = aws_s3_bucket.secure_uploads.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.s3_encryption.arn
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

# S3 Bucket public access block
resource "aws_s3_bucket_public_access_block" "secure_uploads" {
  bucket = aws_s3_bucket.secure_uploads.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# S3 Bucket logging
resource "aws_s3_bucket" "access_logs" {
  bucket = "${local.common_name}-access-logs"

  tags = {
    Name = "${local.common_name}-access-logs"
  }
}

resource "aws_s3_bucket_public_access_block" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_logging" "secure_uploads" {
  bucket = aws_s3_bucket.secure_uploads.id

  target_bucket = aws_s3_bucket.access_logs.id
  target_prefix = "access-logs/"
}

# S3 Bucket lifecycle configuration - FIXED
resource "aws_s3_bucket_lifecycle_configuration" "secure_uploads" {
  bucket = aws_s3_bucket.secure_uploads.id

  rule {
    id     = "multipart_cleanup"
    status = "Enabled"

    # Add required filter block
    filter {}

    abort_incomplete_multipart_upload {
      days_after_initiation = 1
    }
  }

  rule {
    id     = "transition_to_ia"
    status = "Enabled"

    # Add required filter block
    filter {}

    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }

    transition {
      days          = 90
      storage_class = "GLACIER"
    }

    transition {
      days          = 365
      storage_class = "DEEP_ARCHIVE"
    }
  }

  rule {
    id     = "delete_old_versions"
    status = "Enabled"

    # Add required filter block
    filter {}

    noncurrent_version_expiration {
      noncurrent_days = 90
    }
  }
}

# Alternative: Single rule combining all lifecycle policies (more efficient)
# resource "aws_s3_bucket_lifecycle_configuration" "secure_uploads" {
#   bucket = aws_s3_bucket.secure_uploads.id
# 
#   rule {
#     id     = "comprehensive_lifecycle"
#     status = "Enabled"
# 
#     filter {}
# 
#     abort_incomplete_multipart_upload {
#       days_after_initiation = 1
#     }
# 
#     transition {
#       days          = 30
#       storage_class = "STANDARD_IA"
#     }
# 
#     transition {
#       days          = 90
#       storage_class = "GLACIER"
#     }
# 
#     transition {
#       days          = 365
#       storage_class = "DEEP_ARCHIVE"
#     }
# 
#     noncurrent_version_expiration {
#       noncurrent_days = 90
#     }
#   }
# }

# S3 Bucket policy
resource "aws_s3_bucket_policy" "secure_uploads" {
  bucket = aws_s3_bucket.secure_uploads.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyUnSecureCommunications"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.secure_uploads.arn,
          "${aws_s3_bucket.secure_uploads.arn}/*"
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      },
      {
        Sid       = "DenyUnencryptedObjectUploads"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.secure_uploads.arn}/*"
        Condition = {
          StringNotEquals = {
            "s3:x-amz-server-side-encryption" = "aws:kms"
          }
        }
      }
    ]
  })
}

# Get current AWS account ID and region
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}