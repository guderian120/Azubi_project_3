#!/bin/bash

# Secure AWS S3 Upload System Deployment Script
# =============================================

set -e  # Exit on any error
set -u  # Exit on undefined variables

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] WARNING:${NC} $1"
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR:${NC} $1"
    exit 1
}

info() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')] INFO:${NC} $1"
}

# Default values
ENVIRONMENT="dev"
REGION="us-east-1"
PROJECT_NAME="azubi-project-3"
SKIP_TERRAFORM=false
SKIP_PYTHON=false
EMAIL_ALERT=""

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -e|--environment)
            ENVIRONMENT="$2"
            shift 2
            ;;
        -r|--region)
            REGION="$2"
            shift 2
            ;;
        -p|--project-name)
            PROJECT_NAME="$2"
            shift 2
            ;;
        --skip-terraform)
            SKIP_TERRAFORM=true
            shift
            ;;
        --skip-python)
            SKIP_PYTHON=true
            shift
            ;;
        --email-alert)
            EMAIL_ALERT="$2"
            shift 2
            ;;
        -h|--help)
            echo "Usage: $0 [OPTIONS]"
            echo "Options:"
            echo "  -e, --environment      Environment (dev, staging, prod) [default: dev]"
            echo "  -r, --region          AWS region [default: us-east-1]"
            echo "  -p, --project-name    Project name [default: azubi-project-3]"
            echo "  --skip-terraform      Skip Terraform deployment"
            echo "  --skip-python         Skip Python environment setup"
            echo "  --email-alert         Email address for security alerts"
            echo "  -h, --help            Show this help message"
            exit 0
            ;;
        *)
            error "Unknown option: $1"
            ;;
    esac
done

# Verify required tools
check_requirements() {
    log "Checking requirements..."
    
    local required_tools=("aws" "terraform" "python3" "pip3")
    local missing_tools=()
    
    for tool in "${required_tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            missing_tools+=("$tool")
        fi
    done
    
    if [ ${#missing_tools[@]} -ne 0 ]; then
        error "Missing required tools: ${missing_tools[*]}"
    fi
    
    # Check AWS credentials
    if ! aws sts get-caller-identity &> /dev/null; then
        error "AWS credentials not configured. Run 'aws configure' first."
    fi
    
    info "All requirements met"
}

# Setup Python environment
setup_python_env() {
    if [ "$SKIP_PYTHON" = true ]; then
        warn "Skipping Python environment setup"
        return
    fi
    
    log "Setting up Python environment..."
    
    # Create virtual environment if it doesn't exist
    if [ ! -d "venv" ]; then
        python3 -m venv venv
        info "Created Python virtual environment"
    fi
    
    # Activate virtual environment
    source venv/bin/activate
    
    # Upgrade pip
    pip install --upgrade pip
    
    # Install requirements
    if [ -f "requirements.txt" ]; then
        pip install -r requirements.txt
        info "Installed Python dependencies"
    else
        warn "requirements.txt not found"
    fi
}

# Create necessary directories
create_directories() {
    log "Creating necessary directories..."
    
    local dirs=("logs" "backups" "temp" "reports" "config" "scripts" "monitoring")
    
    for dir in "${dirs[@]}"; do
        if [ ! -d "$dir" ]; then
            mkdir -p "$dir"
            info "Created directory: $dir"
        else
            info "Directory already exists: $dir"
        fi
    done
    
    info "All necessary directories are ready"
}

# Deploy Terraform infrastructure
deploy_infrastructure() {
    if [ "$SKIP_TERRAFORM" = true ]; then
        warn "Skipping Terraform deployment"
        return
    fi
    
    log "Deploying AWS infrastructure with Terraform..."
    
    # Check if terraform directory exists
    if [ ! -d "terraform" ]; then
        error "Terraform directory not found. Please ensure terraform configuration files are in ./terraform/"
    fi
    
    cd terraform
    
    # Initialize Terraform
    terraform init
    
    # Create terraform.tfvars file
    cat > terraform.tfvars << EOF
environment = "$ENVIRONMENT"
aws_region = "$REGION"
project_name = "$PROJECT_NAME"
owner = "$(whoami)"
cost_center = "engineering"
EOF
    
    if [ -n "$EMAIL_ALERT" ]; then
        echo "sns_email_endpoint = \"$EMAIL_ALERT\"" >> terraform.tfvars
    fi
    
    # Plan deployment
    terraform plan -var-file=terraform.tfvars -out=tfplan
    
    # Ask for confirmation
    echo
    read -p "Do you want to apply the Terraform plan? (y/N): " -n 1 -r
    echo
    
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        # Apply deployment
        terraform apply tfplan
        
        # Extract outputs (with error checking)
        if terraform output s3_bucket_name &> /dev/null; then
            BUCKET_NAME=$(terraform output -raw s3_bucket_name)
            ACCESS_LOGS_BUCKET=$(terraform output -raw access_logs_bucket_name 2>/dev/null || echo "")
            KMS_KEY_ID=$(terraform output -raw kms_key_id 2>/dev/null || echo "")
            UPLOAD_ROLE_ARN=$(terraform output -raw upload_role_arn 2>/dev/null || echo "")
            ADMIN_ROLE_ARN=$(terraform output -raw admin_role_arn 2>/dev/null || echo "")
            READONLY_ROLE_ARN=$(terraform output -raw readonly_role_arn 2>/dev/null || echo "")
            SNS_TOPIC_ARN=$(terraform output -raw sns_topic_arn 2>/dev/null || echo "")
            
            log "Infrastructure deployed successfully"
            
            # Save outputs to .env file
            cd ..
            create_env_file
        else
            warn "Could not extract Terraform outputs. Infrastructure may not be fully deployed."
            cd ..
            return 1
        fi
    else
        warn "Terraform deployment cancelled"
        cd ..
        return
    fi
    
    cd ..
}

# Create .env file with Terraform outputs
create_env_file() {
    log "Creating .env file with deployment outputs..."
    
    cat > .env << EOF
# Generated by deployment script on $(date)
AWS_REGION=${REGION}
ENVIRONMENT=${ENVIRONMENT}
PROJECT_NAME=${PROJECT_NAME}

# S3 Configuration
S3_BUCKET_NAME=${BUCKET_NAME:-""}
ACCESS_LOGS_BUCKET_NAME=${ACCESS_LOGS_BUCKET:-""}
KMS_KEY_ID=${KMS_KEY_ID:-""}

# IAM Role ARNs
UPLOAD_ROLE_ARN=${UPLOAD_ROLE_ARN:-""}
ADMIN_ROLE_ARN=${ADMIN_ROLE_ARN:-""}
READONLY_ROLE_ARN=${READONLY_ROLE_ARN:-""}

# SNS Configuration
SNS_TOPIC_ARN=${SNS_TOPIC_ARN:-""}

# Application Configuration
LOG_LEVEL=INFO
ENABLE_MFA=true
ENABLE_CLOUDTRAIL=true
ENABLE_CONFIG=true

# Monitoring Configuration
MONITORING_INTERVAL_MINUTES=5
EOF
    
    if [ -n "$EMAIL_ALERT" ]; then
        echo "ALERT_EMAIL=$EMAIL_ALERT" >> .env
    fi
    
    info ".env file created"
}

# Setup monitoring
setup_monitoring() {
    log "Setting up monitoring configuration..."
    
    # Create config directory if it doesn't exist
    mkdir -p config
    
    # Create sample upload config if it doesn't exist
    if [ ! -f "config/upload_config.json" ]; then
        cat > config/upload_config.json << EOF
{
    "bucket_name": "\${S3_BUCKET_NAME}",
    "kms_key_id": "\${KMS_KEY_ID}",
    "aws_region": "\${AWS_REGION}",
    "max_file_size_mb": 100,
    "allowed_extensions": [".txt", ".pdf", ".doc", ".docx", ".jpg", ".png"],
    "upload_timeout_seconds": 300,
    "enable_virus_scan": true,
    "enable_content_validation": true
}
EOF
        info "Created sample upload configuration"
    fi
    
    # Update configuration files with actual values if .env exists
    if [ -f ".env" ]; then
        source .env
        
        # Update upload config with actual values
        if [ -n "$S3_BUCKET_NAME" ]; then
            sed -i "s/\${S3_BUCKET_NAME}/$S3_BUCKET_NAME/g" config/upload_config.json
        fi
        if [ -n "$KMS_KEY_ID" ]; then
            sed -i "s/\${KMS_KEY_ID}/$KMS_KEY_ID/g" config/upload_config.json
        fi
        if [ -n "$AWS_REGION" ]; then
            sed -i "s/\${AWS_REGION}/$AWS_REGION/g" config/upload_config.json
        fi
        
        info "Configuration files updated with deployment values"
    fi
    
    # Setup log rotation
    setup_log_rotation
}

# Setup log rotation
setup_log_rotation() {
    log "Setting up log rotation..."
    
    # Create logrotate configuration
    cat > /tmp/secure-upload-logrotate << EOF
logs/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 0644 $(whoami) $(whoami)
    postrotate
        # Restart monitoring services if needed
        # systemctl reload secure-upload-monitor || true
    endscript
}
EOF
    
    # Install logrotate configuration (requires sudo)
    if command -v sudo &> /dev/null && sudo -n true 2>/dev/null; then
        sudo cp /tmp/secure-upload-logrotate /etc/logrotate.d/secure-upload
        sudo chmod 644 /etc/logrotate.d/secure-upload
        info "Log rotation configured system-wide"
    else
        warn "Could not configure system log rotation (sudo not available or requires password)"
        cp /tmp/secure-upload-logrotate logs/logrotate.conf
        info "Log rotation config saved to logs/logrotate.conf"
    fi
    
    rm -f /tmp/secure-upload-logrotate
}

# Test deployment
test_deployment() {
    log "Testing deployment..."
    
    if [ ! -f ".env" ]; then
        warn "No .env file found, creating minimal version for testing"
        cat > .env << EOF
AWS_REGION=${REGION}
ENVIRONMENT=${ENVIRONMENT}
PROJECT_NAME=${PROJECT_NAME}
EOF
    fi
    
    source .env
    
    # Test Python scripts if they exist
    if [ "$SKIP_PYTHON" != true ]; then
        if [ -f "venv/bin/activate" ]; then
            source venv/bin/activate
            
            # Test upload script help if it exists
            if [ -f "scripts/secure_upload.py" ]; then
                if python3 scripts/secure_upload.py --help &> /dev/null; then
                    info "Upload script is working"
                else
                    warn "Upload script has issues"
                fi
            else
                info "Upload script not found (this is normal for initial setup)"
            fi
            
            # Test monitoring script help if it exists
            if [ -f "monitoring/s3_monitor.py" ]; then
                if python3 monitoring/s3_monitor.py --help &> /dev/null; then
                    info "Monitoring script is working"
                else
                    warn "Monitoring script has issues"
                fi
            else
                info "Monitoring script not found (this is normal for initial setup)"
            fi
        else
            warn "Python virtual environment not found"
        fi
    fi
    
    # Test AWS connectivity if resources exist
    if [ -n "${S3_BUCKET_NAME:-}" ]; then
        if aws s3 ls "s3://$S3_BUCKET_NAME" &> /dev/null; then
            info "S3 bucket is accessible"
        else
            warn "Cannot access S3 bucket"
        fi
    fi
    
    # Test KMS key if it exists
    if [ -n "${KMS_KEY_ID:-}" ]; then
        if aws kms describe-key --key-id "$KMS_KEY_ID" &> /dev/null; then
            info "KMS key is accessible"
        else
            warn "Cannot access KMS key"
        fi
    fi
    
    info "Deployment testing completed"
}

# Create sample test file
create_test_file() {
    log "Creating sample test file..."
    
    # Ensure temp directory exists
    mkdir -p temp
    
    local test_file="temp/test_upload.txt"
    cat > "$test_file" << EOF
This is a test file for the secure upload system.
Generated on: $(date)
Environment: $ENVIRONMENT
Region: $REGION
Project: $PROJECT_NAME
File size: Small test file
Content: Safe test content for upload validation

This file can be used to test the secure upload functionality.
EOF
    
    info "Test file created: $test_file"
    
    # Create additional test files
    echo '{"test": "json data", "timestamp": "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'"}' > temp/test_data.json
    info "Additional test file created: temp/test_data.json"
    
    echo "You can test uploads with:"
    echo "  python3 scripts/secure_upload.py --file $test_file"
    echo "  python3 scripts/secure_upload.py --file temp/test_data.json"
}

# Print deployment summary
print_summary() {
    echo
    echo "========================================="
    echo "       DEPLOYMENT SUMMARY"
    echo "========================================="
    echo "Environment: $ENVIRONMENT"
    echo "Region: $REGION"
    echo "Project: $PROJECT_NAME"
    
    if [ -f ".env" ]; then
        source .env
        echo
        echo "Resources Created:"
        if [ -n "${S3_BUCKET_NAME:-}" ]; then
            echo "- S3 Bucket: $S3_BUCKET_NAME"
        fi
        if [ -n "${ACCESS_LOGS_BUCKET_NAME:-}" ]; then
            echo "- Access Logs Bucket: $ACCESS_LOGS_BUCKET_NAME"
        fi
        if [ -n "${KMS_KEY_ID:-}" ]; then
            echo "- KMS Key: $KMS_KEY_ID"
        fi
        if [ -n "${SNS_TOPIC_ARN:-}" ]; then
            echo "- SNS Topic: $SNS_TOPIC_ARN"
        fi
        
        echo
        echo "IAM Roles:"
        if [ -n "${UPLOAD_ROLE_ARN:-}" ]; then
            echo "- Upload Role: $UPLOAD_ROLE_ARN"
        fi
        if [ -n "${ADMIN_ROLE_ARN:-}" ]; then
            echo "- Admin Role: $ADMIN_ROLE_ARN"
        fi
        if [ -n "${READONLY_ROLE_ARN:-}" ]; then
            echo "- ReadOnly Role: $READONLY_ROLE_ARN"
        fi
    fi
    
    echo
    echo "Files Created:"
    echo "- Configuration: .env"
    echo "- Upload Config: config/upload_config.json"
    echo "- Test Files: temp/test_upload.txt, temp/test_data.json"
    
    echo
    echo "Next Steps:"
    echo "1. Review the .env file and update any additional settings"
    echo "2. Set up your Python application scripts in the scripts/ directory"
    echo "3. Test file uploads: python3 scripts/secure_upload.py --file temp/test_upload.txt"
    echo "4. Start monitoring: python3 monitoring/s3_monitor.py --continuous"
    echo "5. Setup SNS email subscription if not done automatically"
    
    if [ -n "${EMAIL_ALERT:-}" ]; then
        echo "6. Check your email ($EMAIL_ALERT) for SNS subscription confirmation"
    fi
    
    echo
    echo "Documentation: See README.md for detailed usage instructions"
    echo "Log files: logs/ directory"
    echo "========================================="
}

# Cleanup function for failed deployments
cleanup_on_error() {
    error "Deployment failed. Cleaning up..."
    
    if [ -d "terraform" ] && [ ! "$SKIP_TERRAFORM" = true ]; then
        cd terraform 2>/dev/null || return
        if [ -f "tfplan" ]; then
            warn "Terraform plan exists. You may want to run 'terraform destroy' to clean up resources"
        fi
        cd .. 2>/dev/null || return
    fi
}

# Set up error handling
trap cleanup_on_error ERR

# Main deployment workflow
main() {
    log "Starting secure upload system deployment..."
    log "Environment: $ENVIRONMENT, Region: $REGION, Project: $PROJECT_NAME"
    
    check_requirements
    create_directories
    setup_python_env
    deploy_infrastructure
    setup_monitoring
    test_deployment
    create_test_file
    print_summary
    
    log "Deployment completed successfully!"
}

# Run main function
main "$@"