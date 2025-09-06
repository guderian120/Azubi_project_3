# Secure AWS S3 Multipart Upload System

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![AWS](https://img.shields.io/badge/AWS-%23FF9900.svg?style=flat&logo=amazon-aws&logoColor=white)](https://aws.amazon.com/)
[![Terraform](https://img.shields.io/badge/terraform-%235835CC.svg?style=flat&logo=terraform&logoColor=white)](https://terraform.io/)
[![Python](https://img.shields.io/badge/python-3.8+-blue.svg?style=flat&logo=python&logoColor=white)](https://python.org)

## 🚀 Overview

A **production-ready, enterprise-grade** secure file upload system built on AWS S3 with advanced security features, comprehensive monitoring, and automated threat detection. This system implements security best practices and provides a complete solution for organizations requiring secure, scalable file uploads with detailed audit trails.

### ✨ Key Features

- 🔒 **Advanced Security**: KMS encryption, IAM roles, MFA support
- 📊 **Comprehensive Monitoring**: Real-time security analysis and alerting
- 🏗️ **Infrastructure as Code**: Complete Terraform automation
- 🔍 **Threat Detection**: Automated analysis of access patterns
- 📋 **Compliance Ready**: AWS Config rules and CloudTrail integration
- 🚀 **High Performance**: Multipart uploads with progress tracking
- 🛡️ **Zero Trust Architecture**: Least privilege access principles

## 🏛️ Architecture

### Core Components

| Component | Purpose | Technology |
|-----------|---------|------------|
| **S3 Bucket** | Secure file storage with versioning | AWS S3 |
| **KMS Encryption** | Data encryption at rest and in transit | AWS KMS |
| **IAM Roles** | Role-based access control (RBAC) | AWS IAM |
| **CloudTrail** | Comprehensive audit logging | AWS CloudTrail |
| **CloudWatch** | Metrics, monitoring, and alerting | AWS CloudWatch |
| **SNS** | Security notifications and alerts | AWS SNS |
| **Config** | Compliance monitoring and rules | AWS Config |
| **Upload Engine** | Secure multipart upload system | Python/Boto3 |
| **Security Monitor** | Real-time threat detection | Python |

### Security Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Client App    │────│  Upload Script  │────│   S3 Bucket     │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                │                        │
                                │                        │
                       ┌─────────────────┐    ┌─────────────────┐
                       │   IAM Roles     │    │   KMS Key       │
                       └─────────────────┘    └─────────────────┘
                                │                        │
                       ┌─────────────────┐    ┌─────────────────┐
                       │   CloudTrail    │────│  S3 Monitor     │
                       └─────────────────┘    └─────────────────┘
                                │                        │
                       ┌─────────────────┐    ┌─────────────────┐
                       │   CloudWatch    │────│     SNS         │
                       └─────────────────┘    └─────────────────┘
```

## 🚀 Quick Start

### Prerequisites

- **AWS CLI** configured with appropriate permissions
- **Terraform** >= 1.0
- **Python** >= 3.8
- **Git** for version control

### 1-Minute Deploy

```bash
# Clone and setup
git clone <repository>
cd project_3

# One-command deployment
./scripts/deploy.sh --environment prod --email-alert admin@company.com

# Test upload
python3 scripts/secure_upload.py --file test.txt

# Start monitoring
python3 monitoring/s3_monitor.py --continuous
```

### Manual Deployment

1. **Environment Setup**
   ```bash
   # Create Python virtual environment
   python3 -m venv venv
   source venv/bin/activate
   
   # Install dependencies
   pip install -r requirements.txt
   
   # Configure AWS credentials
   aws configure
   ```

2. **Deploy Infrastructure**
   ```bash
   cd terraform
   terraform init
   terraform plan -var="environment=prod"
   terraform apply
   ```

3. **Configure Environment**
   ```bash
   # Copy environment template
   cp .env.template .env
   
   # Update with Terraform outputs
   # (automatically done by deploy script)
   ```

## 📖 Usage Guide

### File Upload

#### Basic Upload
```bash
# Simple file upload
python3 scripts/secure_upload.py --file document.pdf

# Upload with custom metadata
python3 scripts/secure_upload.py \
  --file sensitive_data.zip \
  --metadata '{"department": "finance", "classification": "confidential"}' \
  --tags '{"environment": "prod", "backup": "required"}'
```

#### Advanced Upload Options
```bash
# Upload assuming specific IAM role
python3 scripts/secure_upload.py \
  --file large_dataset.tar.gz \
  --role-arn arn:aws:iam::123456789012:role/DataUploadRole \
  --verbose

# Upload to custom S3 key path
python3 scripts/secure_upload.py \
  --file report.xlsx \
  --key "reports/2024/Q1/financial_report.xlsx"
```

### Security Monitoring

#### Real-time Monitoring
```bash
# Start continuous monitoring
python3 monitoring/s3_monitor.py \
  --bucket secure-upload-bucket \
  --logs-bucket access-logs-bucket \
  --continuous \
  --interval 5 \
  --sns-topic arn:aws:sns:us-east-1:123456789012:security-alerts
```

#### Historical Analysis
```bash
# Analyze last 7 days
python3 monitoring/s3_monitor.py \
  --bucket secure-upload-bucket \
  --logs-bucket access-logs-bucket \
  --start-date 2024-01-01 \
  --end-date 2024-01-07 \
  --output-format json \
  --output-file security_report.json
```

### System Management

#### Health Checks
```bash
# Check system health
python3 scripts/manage.py health

# Get usage statistics
python3 scripts/manage.py stats --days 30

# List recent uploads
python3 scripts/manage.py list-files --days 7
```

#### File Management
```bash
# Delete specific file
python3 scripts/manage.py delete-file "uploads/2024/01/15/abc123_document.pdf"

# Cleanup old files (dry run)
python3 scripts/manage.py cleanup --days 90 --dry-run

# Actual cleanup
python3 scripts/manage.py cleanup --days 90
```

## 🔧 Configuration

### Environment Variables

The system uses environment variables for configuration. Key variables include:

```bash
# AWS Configuration
AWS_REGION=us-east-1
S3_BUCKET_NAME=your-secure-bucket
KMS_KEY_ID=your-kms-key-id

# Security Settings
ENABLE_MFA=true
MAX_FILE_SIZE_GB=5
ALLOWED_FILE_EXTENSIONS=".pdf,.docx,.xlsx,.zip"

# Monitoring
MONITORING_INTERVAL_MINUTES=5
ALERT_EMAIL=security@company.com
SNS_TOPIC_ARN=arn:aws:sns:...
```

### Configuration Files

- `config/upload_config.json` - Upload system settings
- `config/monitor_config.json` - Monitoring and alerting rules
- `.env` - Environment variables (auto-generated)

### Terraform Variables

```hcl
# terraform.tfvars
environment        = "production"
aws_region        = "us-east-1"
project_name      = "secure-upload"
enable_mfa        = true
enable_cloudtrail = true
enable_config     = true
sns_email_endpoint = "admin@company.com"
```

## 🔒 Security Features

### Encryption
- **At Rest**: AES-256 encryption using AWS KMS customer-managed keys
- **In Transit**: TLS 1.2+ enforced for all communications
- **Key Rotation**: Automatic annual key rotation enabled

### Access Control
- **IAM Roles**: Separate roles for upload, admin, and read-only access
- **MFA Required**: Multi-factor authentication for sensitive operations
- **Least Privilege**: Minimal required permissions per role
- **IP Restrictions**: Optional IP-based access controls

### Monitoring & Alerting
- **Real-time Analysis**: Continuous monitoring of access patterns
- **Threat Detection**: Automated detection of suspicious activities
- **Compliance Monitoring**: AWS Config rules for security compliance
- **Audit Logging**: Comprehensive CloudTrail integration

### Security Controls

| Control | Implementation | Purpose |
|---------|----------------|----------|
| Data Encryption | KMS + SSE-KMS | Protect data at rest |
| Transit Security | TLS 1.2+ | Secure data in transit |
| Access Logging | CloudTrail + S3 logs | Audit trail |
| Access Control | IAM + Bucket Policies | Authorize access |
| Threat Detection | Custom monitoring | Detect anomalies |
| Compliance | AWS Config | Meet requirements |

## 📊 Monitoring & Alerts

### Alert Types

| Alert | Severity | Trigger | Action |
|-------|----------|---------|--------|
| Excessive Failed Requests | HIGH | >10 failures/min from IP | Block + Notify |
| Suspicious User Agent | MEDIUM | Known attack tools | Monitor + Log |
| Unauthorized Operations | HIGH | Failed admin operations | Alert + Audit |
| Large File Upload | LOW | Files >1GB | Monitor usage |
| Geographic Anomaly | MEDIUM | Access from new regions | Verify + Log |

### Dashboards

- **Security Dashboard**: Real-time threat indicators
- **Usage Dashboard**: Upload statistics and trends  
- **Compliance Dashboard**: Security posture metrics
- **Performance Dashboard**: System performance metrics

## 🧪 Testing

### Run Test Suite
```bash
# Run all tests
python3 tests/test_secure_upload.py

# Run specific test category
python3 -m pytest tests/ -k "test_security"

# Run with coverage
python3 -m pytest tests/ --cov=scripts --cov=monitoring
```

### Test Categories
- **Unit Tests**: Core functionality validation
- **Integration Tests**: AWS service integration
- **Security Tests**: Vulnerability assessment  
- **Performance Tests**: Load and stress testing
- **Compliance Tests**: Regulatory requirement validation

## 📚 API Reference

### Upload API

```python
from scripts.secure_upload import SecureUploadManager, UploadConfig

# Initialize
config = UploadConfig(
    bucket_name="my-secure-bucket",
    kms_key_id="alias/my-upload-key",
    region="us-east-1"
)
manager = SecureUploadManager(config)

# Upload file
result = manager.upload_file(
    file_path="document.pdf",
    metadata={"department": "legal"},
    tags={"classification": "internal"}
)
```

### Monitor API

```python
from monitoring.s3_monitor import S3SecurityMonitor

# Initialize monitor
monitor = S3SecurityMonitor(
    bucket_name="my-secure-bucket",
    access_logs_bucket="my-logs-bucket"
)

# Analyze security
alerts = monitor.analyze_security_threats(log_entries)
```

## 🛠️ Troubleshooting

### Common Issues

#### Upload Failures
```bash
# Check permissions
aws sts get-caller-identity
aws s3 ls s3://your-bucket-name

# Verify KMS access
aws kms describe-key --key-id alias/your-key-alias
```

#### Monitoring Issues
```bash
# Check CloudTrail status
aws cloudtrail get-trail-status --name your-trail-name

# Verify S3 access logs
aws s3 ls s3://your-access-logs-bucket/access-logs/
```

#### Permission Errors
```bash
# Assume upload role
aws sts assume-role --role-arn arn:aws:iam::ACCOUNT:role/upload-role \
  --role-session-name upload-session

# Test with assumed credentials
export AWS_ACCESS_KEY_ID=<temporary-key>
export AWS_SECRET_ACCESS_KEY=<temporary-secret>
export AWS_SESSION_TOKEN=<session-token>
```

### Debug Mode

```bash
# Enable verbose logging
export LOG_LEVEL=DEBUG

# Run with debug output
python3 scripts/secure_upload.py --file test.txt --verbose
```

## 🔄 Backup & Recovery

### Configuration Backup
```bash
# Backup system configuration
python3 scripts/manage.py backup --output config_backup.json

# Backup Terraform state
cd terraform
terraform state pull > terraform_backup.tfstate
```

### Disaster Recovery
```bash
# Restore from backup
terraform state push terraform_backup.tfstate
terraform plan
terraform apply
```

## 🔧 Customization

### Adding Custom Validations

```python
# Extend SecureUploadManager
class CustomUploadManager(SecureUploadManager):
    def _custom_validation(self, file_path: str) -> bool:
        # Add your custom validation logic
        return True
```

### Custom Alert Rules

```json
// config/monitor_config.json
{
  "custom_rules": {
    "rule_name": {
      "condition": "failed_requests > 50",
      "severity": "CRITICAL",
      "action": "block_ip"
    }
  }
}
```

## 🤝 Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open Pull Request

### Development Setup

```bash
# Install development dependencies
pip install -r requirements-dev.txt

# Setup pre-commit hooks
pre-commit install

# Run linting
flake8 scripts/ monitoring/
black scripts/ monitoring/
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

- **Documentation**: [Wiki](wiki)
- **Issues**: [GitHub Issues](issues)
- **Discussions**: [GitHub Discussions](discussions)
- **Email**: support@company.com

## 📈 Roadmap

- [ ] **Web UI**: Browser-based upload interface
- [ ] **API Gateway**: REST API for programmatic access
- [ ] **Multi-region**: Cross-region replication support
- [ ] **ML Detection**: Machine learning-based anomaly detection
- [ ] **Mobile SDK**: iOS/Android upload libraries
- [ ] **Advanced Analytics**: Usage pattern analysis

---

**Built with ❤️ by the DevOps Team**

*For enterprise support and custom implementations, contact our team.*
