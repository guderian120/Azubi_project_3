#!/usr/bin/env python3
"""
Secure Upload System Management Utility
=======================================

Administrative utility for managing the secure upload system.

Features:
- Bulk file operations
- Security policy updates
- User access management
- System health checks
- Backup and restore operations
- Compliance reporting

Author: DevOps Team
Version: 1.0.0
"""

import os
import sys
import json
import logging
import argparse
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Optional

import boto3
import click
from botocore.exceptions import ClientError
from tabulate import tabulate

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/manage.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

class SecureUploadManager:
    """Management utility for the secure upload system."""
    
    def __init__(self):
        """Initialize the manager."""
        self._load_config()
        self._setup_aws_clients()
    
    def _load_config(self):
        """Load configuration from environment variables."""
        from dotenv import load_dotenv
        load_dotenv()
        
        self.bucket_name = os.getenv('S3_BUCKET_NAME')
        self.access_logs_bucket = os.getenv('ACCESS_LOGS_BUCKET_NAME')
        self.kms_key_id = os.getenv('KMS_KEY_ID')
        self.region = os.getenv('AWS_REGION', 'us-east-1')
        self.sns_topic_arn = os.getenv('SNS_TOPIC_ARN')
        
        if not all([self.bucket_name, self.kms_key_id]):
            raise ValueError("Missing required environment variables. Check .env file.")
    
    def _setup_aws_clients(self):
        """Setup AWS service clients."""
        self.s3_client = boto3.client('s3', region_name=self.region)
        self.kms_client = boto3.client('kms', region_name=self.region)
        self.iam_client = boto3.client('iam', region_name=self.region)
        self.sns_client = boto3.client('sns', region_name=self.region)
        self.cloudwatch_client = boto3.client('cloudwatch', region_name=self.region)
    
    def list_uploads(self, prefix: str = 'uploads/', days: int = 30) -> List[Dict]:
        """List uploaded files.
        
        Args:
            prefix: S3 key prefix to filter
            days: Number of days to look back
            
        Returns:
            List of file information dictionaries
        """
        try:
            files = []
            cutoff_date = datetime.now() - timedelta(days=days)
            
            paginator = self.s3_client.get_paginator('list_objects_v2')
            
            for page in paginator.paginate(Bucket=self.bucket_name, Prefix=prefix):
                if 'Contents' not in page:
                    continue
                
                for obj in page['Contents']:
                    if obj['LastModified'].replace(tzinfo=None) < cutoff_date:
                        continue
                    
                    # Get additional metadata
                    try:
                        metadata_response = self.s3_client.head_object(
                            Bucket=self.bucket_name,
                            Key=obj['Key']
                        )
                        
                        files.append({
                            'key': obj['Key'],
                            'size': obj['Size'],
                            'last_modified': obj['LastModified'].isoformat(),
                            'storage_class': obj.get('StorageClass', 'STANDARD'),
                            'etag': obj['ETag'].strip('"'),
                            'encrypted': metadata_response.get('ServerSideEncryption', 'None') != 'None',
                            'kms_key': metadata_response.get('SSEKMSKeyId', ''),
                            'metadata': metadata_response.get('Metadata', {}),
                            'version_id': metadata_response.get('VersionId', '')
                        })
                    except ClientError as e:
                        logger.warning(f"Failed to get metadata for {obj['Key']}: {str(e)}")
                        files.append({
                            'key': obj['Key'],
                            'size': obj['Size'],
                            'last_modified': obj['LastModified'].isoformat(),
                            'error': str(e)
                        })
            
            return files
            
        except ClientError as e:
            logger.error(f"Failed to list uploads: {str(e)}")
            return []
    
    def delete_file(self, key: str, confirm: bool = False) -> bool:
        """Delete a file from S3.
        
        Args:
            key: S3 object key
            confirm: Skip confirmation prompt
            
        Returns:
            True if successful, False otherwise
        """
        try:
            if not confirm:
                response = input(f"Are you sure you want to delete '{key}'? (y/N): ")
                if response.lower() != 'y':
                    logger.info("Deletion cancelled")
                    return False
            
            self.s3_client.delete_object(Bucket=self.bucket_name, Key=key)
            logger.info(f"Deleted file: {key}")
            return True
            
        except ClientError as e:
            logger.error(f"Failed to delete file {key}: {str(e)}")
            return False
    
    def cleanup_old_files(self, days: int = 90, dry_run: bool = True) -> Dict:
        """Clean up old files based on age.
        
        Args:
            days: Files older than this will be deleted
            dry_run: If True, only show what would be deleted
            
        Returns:
            Summary of cleanup operation
        """
        cutoff_date = datetime.now() - timedelta(days=days)
        files_to_delete = []
        total_size = 0
        
        try:
            paginator = self.s3_client.get_paginator('list_objects_v2')
            
            for page in paginator.paginate(Bucket=self.bucket_name):
                if 'Contents' not in page:
                    continue
                
                for obj in page['Contents']:
                    if obj['LastModified'].replace(tzinfo=None) < cutoff_date:
                        files_to_delete.append({
                            'key': obj['Key'],
                            'size': obj['Size'],
                            'last_modified': obj['LastModified']
                        })
                        total_size += obj['Size']
            
            if dry_run:
                logger.info(f"DRY RUN: Would delete {len(files_to_delete)} files ({total_size:,} bytes)")
                return {
                    'dry_run': True,
                    'files_found': len(files_to_delete),
                    'total_size': total_size,
                    'files': files_to_delete[:10]  # Show first 10
                }
            
            # Actually delete files
            deleted_count = 0
            for file_info in files_to_delete:
                try:
                    self.s3_client.delete_object(Bucket=self.bucket_name, Key=file_info['key'])
                    deleted_count += 1
                    logger.debug(f"Deleted: {file_info['key']}")
                except ClientError as e:
                    logger.error(f"Failed to delete {file_info['key']}: {str(e)}")
            
            logger.info(f"Cleanup completed: {deleted_count}/{len(files_to_delete)} files deleted")
            
            return {
                'dry_run': False,
                'files_found': len(files_to_delete),
                'files_deleted': deleted_count,
                'total_size': total_size
            }
            
        except ClientError as e:
            logger.error(f"Cleanup failed: {str(e)}")
            return {'error': str(e)}
    
    def get_system_health(self) -> Dict:
        """Get system health status.
        
        Returns:
            System health information
        """
        health = {
            'timestamp': datetime.now().isoformat(),
            'overall_status': 'HEALTHY',
            'services': {}
        }
        
        # Check S3 bucket
        try:
            self.s3_client.head_bucket(Bucket=self.bucket_name)
            health['services']['s3_main_bucket'] = 'HEALTHY'
        except ClientError:
            health['services']['s3_main_bucket'] = 'UNHEALTHY'
            health['overall_status'] = 'DEGRADED'
        
        # Check access logs bucket
        if self.access_logs_bucket:
            try:
                self.s3_client.head_bucket(Bucket=self.access_logs_bucket)
                health['services']['s3_logs_bucket'] = 'HEALTHY'
            except ClientError:
                health['services']['s3_logs_bucket'] = 'UNHEALTHY'
                health['overall_status'] = 'DEGRADED'
        
        # Check KMS key
        try:
            response = self.kms_client.describe_key(KeyId=self.kms_key_id)
            if response['KeyMetadata']['Enabled']:
                health['services']['kms_key'] = 'HEALTHY'
            else:
                health['services']['kms_key'] = 'DISABLED'
                health['overall_status'] = 'DEGRADED'
        except ClientError:
            health['services']['kms_key'] = 'UNHEALTHY'
            health['overall_status'] = 'DEGRADED'
        
        # Check SNS topic
        if self.sns_topic_arn:
            try:
                self.sns_client.get_topic_attributes(TopicArn=self.sns_topic_arn)
                health['services']['sns_topic'] = 'HEALTHY'
            except ClientError:
                health['services']['sns_topic'] = 'UNHEALTHY'
                health['overall_status'] = 'DEGRADED'
        
        return health
    
    def get_usage_stats(self, days: int = 30) -> Dict:
        """Get usage statistics.
        
        Args:
            days: Number of days to analyze
            
        Returns:
            Usage statistics
        """
        try:
            end_time = datetime.now()
            start_time = end_time - timedelta(days=days)
            
            # Get CloudWatch metrics
            metrics = {}
            
            # Upload count metric (if available)
            try:
                response = self.cloudwatch_client.get_metric_statistics(
                    Namespace='AWS/S3',
                    MetricName='NumberOfObjects',
                    Dimensions=[
                        {
                            'Name': 'BucketName',
                            'Value': self.bucket_name
                        },
                        {
                            'Name': 'StorageType',
                            'Value': 'AllStorageTypes'
                        }
                    ],
                    StartTime=start_time,
                    EndTime=end_time,
                    Period=86400,  # Daily
                    Statistics=['Average']
                )
                
                if response['Datapoints']:
                    metrics['object_count'] = response['Datapoints'][-1]['Average']
            except ClientError:
                pass
            
            # Bucket size metric
            try:
                response = self.cloudwatch_client.get_metric_statistics(
                    Namespace='AWS/S3',
                    MetricName='BucketSizeBytes',
                    Dimensions=[
                        {
                            'Name': 'BucketName',
                            'Value': self.bucket_name
                        },
                        {
                            'Name': 'StorageType',
                            'Value': 'StandardStorage'
                        }
                    ],
                    StartTime=start_time,
                    EndTime=end_time,
                    Period=86400,
                    Statistics=['Average']
                )
                
                if response['Datapoints']:
                    metrics['bucket_size_bytes'] = response['Datapoints'][-1]['Average']
            except ClientError:
                pass
            
            # Manual count from S3
            file_count = 0
            total_size = 0
            
            paginator = self.s3_client.get_paginator('list_objects_v2')
            for page in paginator.paginate(Bucket=self.bucket_name):
                if 'Contents' in page:
                    file_count += len(page['Contents'])
                    total_size += sum(obj['Size'] for obj in page['Contents'])
            
            return {
                'analysis_period_days': days,
                'file_count': file_count,
                'total_size_bytes': total_size,
                'total_size_gb': total_size / (1024**3),
                'cloudwatch_metrics': metrics,
                'generated_at': datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Failed to get usage stats: {str(e)}")
            return {'error': str(e)}
    
    def backup_configuration(self, output_path: str) -> bool:
        """Backup system configuration.
        
        Args:
            output_path: Path to save backup
            
        Returns:
            True if successful
        """
        try:
            backup_data = {
                'timestamp': datetime.now().isoformat(),
                'system_config': {
                    'bucket_name': self.bucket_name,
                    'access_logs_bucket': self.access_logs_bucket,
                    'kms_key_id': self.kms_key_id,
                    'region': self.region,
                    'sns_topic_arn': self.sns_topic_arn
                },
                'bucket_policy': {},
                'iam_roles': {},
                'kms_key_policy': {}
            }
            
            # Get bucket policy
            try:
                policy_response = self.s3_client.get_bucket_policy(Bucket=self.bucket_name)
                backup_data['bucket_policy'] = json.loads(policy_response['Policy'])
            except ClientError:
                logger.warning("Could not retrieve bucket policy")
            
            # Get KMS key policy
            try:
                policy_response = self.kms_client.get_key_policy(
                    KeyId=self.kms_key_id,
                    PolicyName='default'
                )
                backup_data['kms_key_policy'] = json.loads(policy_response['Policy'])
            except ClientError:
                logger.warning("Could not retrieve KMS key policy")
            
            # Save backup
            with open(output_path, 'w') as f:
                json.dump(backup_data, f, indent=2, default=str)
            
            logger.info(f"Configuration backup saved to: {output_path}")
            return True
            
        except Exception as e:
            logger.error(f"Backup failed: {str(e)}")
            return False


# CLI interface
@click.group()
def cli():
    """Secure Upload System Management Utility"""
    pass

@cli.command()
@click.option('--prefix', '-p', default='uploads/', help='S3 key prefix to filter')
@click.option('--days', '-d', default=30, help='Number of days to look back')
@click.option('--format', '-f', type=click.Choice(['table', 'json']), default='table', help='Output format')
def list_files(prefix, days, format):
    """List uploaded files."""
    manager = SecureUploadManager()
    files = manager.list_uploads(prefix, days)
    
    if format == 'json':
        print(json.dumps(files, indent=2, default=str))
    else:
        if files:
            table_data = []
            for file_info in files:
                size_mb = file_info['size'] / (1024 * 1024)
                table_data.append([
                    file_info['key'],
                    f"{size_mb:.2f} MB",
                    file_info['last_modified'][:19],
                    file_info.get('storage_class', 'STANDARD'),
                    '✓' if file_info.get('encrypted', False) else '✗'
                ])
            
            print(tabulate(
                table_data,
                headers=['Key', 'Size', 'Last Modified', 'Storage Class', 'Encrypted'],
                tablefmt='grid'
            ))
            print(f"\nTotal files: {len(files)}")
        else:
            print("No files found")

@cli.command()
@click.argument('key')
@click.option('--confirm', is_flag=True, help='Skip confirmation prompt')
def delete_file(key, confirm):
    """Delete a specific file."""
    manager = SecureUploadManager()
    success = manager.delete_file(key, confirm)
    if success:
        print(f"✓ File deleted: {key}")
    else:
        print(f"✗ Failed to delete file: {key}")

@cli.command()
@click.option('--days', '-d', default=90, help='Delete files older than N days')
@click.option('--dry-run', is_flag=True, help='Show what would be deleted without deleting')
def cleanup(days, dry_run):
    """Clean up old files."""
    manager = SecureUploadManager()
    result = manager.cleanup_old_files(days, dry_run)
    
    if 'error' in result:
        print(f"✗ Cleanup failed: {result['error']}")
        return
    
    if result['dry_run']:
        print(f"DRY RUN: Found {result['files_found']} files to delete")
        print(f"Total size: {result['total_size']:,} bytes ({result['total_size']/(1024**3):.2f} GB)")
        
        if result.get('files'):
            print("\nFirst 10 files that would be deleted:")
            for file_info in result['files'][:10]:
                print(f"  {file_info['key']} ({file_info['last_modified']})")
    else:
        print(f"✓ Cleanup completed")
        print(f"Files deleted: {result['files_deleted']}/{result['files_found']}")
        print(f"Space freed: {result['total_size']:,} bytes ({result['total_size']/(1024**3):.2f} GB)")

@cli.command()
def health():
    """Check system health."""
    manager = SecureUploadManager()
    health = manager.get_system_health()
    
    status_color = {
        'HEALTHY': '🟢',
        'DEGRADED': '🟡', 
        'UNHEALTHY': '🔴',
        'DISABLED': '🟡'
    }
    
    print(f"Overall Status: {status_color.get(health['overall_status'], '⚪')} {health['overall_status']}")
    print(f"Checked at: {health['timestamp']}")
    print("\nService Status:")
    
    for service, status in health['services'].items():
        icon = status_color.get(status, '⚪')
        service_name = service.replace('_', ' ').title()
        print(f"  {icon} {service_name}: {status}")

@cli.command()
@click.option('--days', '-d', default=30, help='Number of days to analyze')
def stats(days):
    """Show usage statistics."""
    manager = SecureUploadManager()
    stats = manager.get_usage_stats(days)
    
    if 'error' in stats:
        print(f"✗ Failed to get stats: {stats['error']}")
        return
    
    print(f"Usage Statistics ({days} days)")
    print("=" * 40)
    print(f"File Count: {stats['file_count']:,}")
    print(f"Total Size: {stats['total_size_bytes']:,} bytes ({stats['total_size_gb']:.2f} GB)")
    print(f"Average File Size: {stats['total_size_bytes']/max(stats['file_count'], 1):,.0f} bytes")
    
    if stats.get('cloudwatch_metrics'):
        print("\nCloudWatch Metrics:")
        for metric, value in stats['cloudwatch_metrics'].items():
            print(f"  {metric}: {value}")

@cli.command()
@click.option('--output', '-o', default='backup.json', help='Output file path')
def backup(output):
    """Backup system configuration."""
    manager = SecureUploadManager()
    success = manager.backup_configuration(output)
    
    if success:
        print(f"✓ Configuration backed up to: {output}")
    else:
        print("✗ Backup failed")

if __name__ == '__main__':
    cli()
