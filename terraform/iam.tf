# IAM Role for File Upload Users
resource "aws_iam_role" "upload_role" {
  name = "${local.common_name}-upload-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        # Condition = {
        #   Bool = {
        #     "aws:MultiFactorAuthPresent" = "true"
        #   }
        # }
      }
    ]
  })

  tags = {
    Name = "${local.common_name}-upload-role"
  }
}

# IAM Policy for Upload Role
resource "aws_iam_policy" "upload_policy" {
  name        = "${local.common_name}-upload-policy"
  description = "Policy for secure file upload operations"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "S3UploadPermissions"
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:PutObjectAcl",
          "s3:GetObject",
          "s3:ListMultipartUploadParts",
          "s3:AbortMultipartUpload",
          "s3:ListBucketMultipartUploads"
        ]
        Resource = [
          aws_s3_bucket.secure_uploads.arn,
          "${aws_s3_bucket.secure_uploads.arn}/*"
        ]
        Condition = {
          StringEquals = {
            "s3:x-amz-server-side-encryption" = "aws:kms"
            "s3:x-amz-server-side-encryption-aws-kms-key-id" = aws_kms_key.s3_encryption.arn
          }
        }
      },
      {
        Sid    = "KMSPermissions"
        Effect = "Allow"
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = aws_kms_key.s3_encryption.arn
      },
      {
        Sid    = "ListBucketPermissions"
        Effect = "Allow"
        Action = [
          "s3:ListBucket",
          "s3:GetBucketLocation"
        ]
        Resource = aws_s3_bucket.secure_uploads.arn
        Condition = {
          StringLike = {
            "s3:prefix" = "uploads/*"
          }
        }
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "upload_policy_attachment" {
  role       = aws_iam_role.upload_role.name
  policy_arn = aws_iam_policy.upload_policy.arn
}

# IAM Role for Admin Users
resource "aws_iam_role" "admin_role" {
  name = "${local.common_name}-admin-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Condition = {
          Bool = {
            "aws:MultiFactorAuthPresent" = "true"
          }
        }
      }
    ]
  })

  tags = {
    Name = "${local.common_name}-admin-role"
  }
}

# IAM Policy for Admin Role
resource "aws_iam_policy" "admin_policy" {
  name        = "${local.common_name}-admin-policy"
  description = "Full administrative policy for S3 bucket management"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "S3FullAccess"
        Effect = "Allow"
        Action = [
          "s3:*"
        ]
        Resource = [
          aws_s3_bucket.secure_uploads.arn,
          "${aws_s3_bucket.secure_uploads.arn}/*",
          aws_s3_bucket.access_logs.arn,
          "${aws_s3_bucket.access_logs.arn}/*"
        ]
      },
      {
        Sid    = "KMSFullAccess"
        Effect = "Allow"
        Action = [
          "kms:*"
        ]
        Resource = aws_kms_key.s3_encryption.arn
      },
      {
        Sid    = "CloudTrailAccess"
        Effect = "Allow"
        Action = [
          "cloudtrail:LookupEvents",
          "cloudtrail:GetTrailStatus"
        ]
        Resource = "*"
      },
      {
        Sid    = "ConfigAccess"
        Effect = "Allow"
        Action = [
          "config:GetComplianceDetailsByConfigRule",
          "config:GetComplianceDetailsByResource",
          "config:DescribeConfigRules"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "admin_policy_attachment" {
  role       = aws_iam_role.admin_role.name
  policy_arn = aws_iam_policy.admin_policy.arn
}

# IAM Role for Read-Only Users
resource "aws_iam_role" "readonly_role" {
  name = "${local.common_name}-readonly-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
      }
    ]
  })

  tags = {
    Name = "${local.common_name}-readonly-role"
  }
}

# IAM Policy for Read-Only Role
resource "aws_iam_policy" "readonly_policy" {
  name        = "${local.common_name}-readonly-policy"
  description = "Read-only access policy for monitoring and auditing"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "S3ReadOnlyAccess"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:ListBucket",
          "s3:GetBucketLocation",
          "s3:GetBucketVersioning",
          "s3:GetBucketPolicy",
          "s3:GetBucketAcl",
          "s3:GetBucketLogging",
          "s3:GetBucketNotification"
        ]
        Resource = [
          aws_s3_bucket.secure_uploads.arn,
          "${aws_s3_bucket.secure_uploads.arn}/*",
          aws_s3_bucket.access_logs.arn,
          "${aws_s3_bucket.access_logs.arn}/*"
        ]
      },
      {
        Sid    = "KMSReadOnlyAccess"
        Effect = "Allow"
        Action = [
          "kms:DescribeKey",
          "kms:GetKeyPolicy",
          "kms:GetKeyRotationStatus",
          "kms:ListKeys",
          "kms:ListAliases"
        ]
        Resource = "*"
      },
      {
        Sid    = "CloudTrailReadAccess"
        Effect = "Allow"
        Action = [
          "cloudtrail:LookupEvents",
          "cloudtrail:GetTrailStatus",
          "cloudtrail:DescribeTrails"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "readonly_policy_attachment" {
  role       = aws_iam_role.readonly_role.name
  policy_arn = aws_iam_policy.readonly_policy.arn
}

# IAM Instance Profile for EC2 instances (if needed)
resource "aws_iam_instance_profile" "upload_instance_profile" {
  name = "${local.common_name}-upload-instance-profile"
  role = aws_iam_role.upload_role.name

  tags = {
    Name = "${local.common_name}-upload-instance-profile"
  }
}
