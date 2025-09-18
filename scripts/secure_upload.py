#!/usr/bin/env python3
"""
Secure AWS S3 Multipart Upload System
=====================================

A comprehensive, secure file upload system using AWS S3 multipart upload
with focus on security, permissions, and monitoring.

Features:
- Secure multipart file uploads to S3
- KMS encryption for data at rest and in transit
- Role-based access control (RBAC)
- Comprehensive logging and monitoring
- File type validation and size limits
- Progress tracking and resume capability
- Automatic cleanup of failed uploads

Author: ANDY AMPONSAH
Version: 1.0.0
"""

import os
import sys
import json
import hashlib
import logging
import argparse
import mimetypes
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor, as_completed

import boto3
import click
from tqdm import tqdm
from botocore.exceptions import ClientError, BotoCoreError
from botocore.config import Config
from cryptography.fernet import Fernet
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/secure_upload.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

@dataclass
class UploadConfig:
    """Configuration class for upload parameters."""
    bucket_name: str
    kms_key_id: str
    region: str = "us-east-1"
    multipart_threshold: int = 100 * 1024 * 1024  # 100 MB
    multipart_chunksize: int = 8 * 1024 * 1024   # 8 MB
    max_file_size: int = 5 * 1024 * 1024 * 1024  # 5 GB
    max_concurrent_uploads: int = 10
    retry_attempts: int = 3
    allowed_extensions: List[str] = None
    
    def __post_init__(self):
        if self.allowed_extensions is None:
            self.allowed_extensions = [
                '.zip', '.tar', '.gz', '.pdf', '.doc', '.docx',
                '.xls', '.xlsx', '.ppt', '.pptx', '.txt', '.csv',
                '.json', '.xml', '.yml', '.yaml'
            ]

class SecureUploadManager:
    """Secure S3 multipart upload manager with comprehensive security features."""
    
    def __init__(self, config: UploadConfig, role_arn: Optional[str] = None):
        """Initialize the secure upload manager.
        
        Args:
            config: Upload configuration
            role_arn: Optional IAM role ARN to assume
        """
        self.config = config
        self.role_arn = role_arn
        self._setup_aws_session()
        self._validate_aws_permissions()
        
    def _setup_aws_session(self):
        """Setup AWS session with proper configuration."""
        try:
            # Configure boto3 with security best practices
            boto_config = Config(
                region_name=self.config.region,
                retries={'max_attempts': self.config.retry_attempts, 'mode': 'adaptive'},
                signature_version='s3v4'
            )
            
            if self.role_arn:
                # Assume role for secure access
                sts_client = boto3.client('sts', config=boto_config)
                response = sts_client.assume_role(
                    RoleArn=self.role_arn,
                    RoleSessionName=f'secure-upload-{datetime.now().strftime("%Y%m%d%H%M%S")}'
                )
                
                credentials = response['Credentials']
                self.s3_client = boto3.client(
                    's3',
                    aws_access_key_id=credentials['AccessKeyId'],
                    aws_secret_access_key=credentials['SecretAccessKey'],
                    aws_session_token=credentials['SessionToken'],
                    config=boto_config
                )
                
                self.kms_client = boto3.client(
                    'kms',
                    aws_access_key_id=credentials['AccessKeyId'],
                    aws_secret_access_key=credentials['SecretAccessKey'],
                    aws_session_token=credentials['SessionToken'],
                    config=boto_config
                )
            else:
                self.s3_client = boto3.client('s3', config=boto_config)
                self.kms_client = boto3.client('kms', config=boto_config)
                
            logger.info(f"AWS session established for region: {self.config.region}")
            
        except Exception as e:
            logger.error(f"Failed to setup AWS session: {str(e)}")
            raise
    
    def _validate_aws_permissions(self):
        """Validate AWS permissions before proceeding."""
        try:
            # Test S3 bucket access
            self.s3_client.head_bucket(Bucket=self.config.bucket_name)
            
            # Test KMS key access
            self.kms_client.describe_key(KeyId=self.config.kms_key_id)
            
            logger.info("AWS permissions validated successfully")
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'NoSuchBucket':
                logger.error(f"S3 bucket '{self.config.bucket_name}' does not exist")
            elif error_code == 'AccessDenied':
                logger.error("Access denied - check IAM permissions")
            else:
                logger.error(f"AWS permission validation failed: {str(e)}")
            raise
    
    def _validate_file(self, file_path: str) -> Tuple[bool, str]:
        """Validate file before upload.
        
        Args:
            file_path: Path to the file to validate
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        try:
            path = Path(file_path)
            
            # Check if file exists
            if not path.exists():
                return False, f"File does not exist: {file_path}"
            
            # Check file size
            file_size = path.stat().st_size
            if file_size > self.config.max_file_size:
                size_mb = file_size / (1024 * 1024)
                max_mb = self.config.max_file_size / (1024 * 1024)
                return False, f"File size ({size_mb:.1f} MB) exceeds limit ({max_mb:.1f} MB)"
            
            # Check file extension
            file_ext = path.suffix.lower()
            if file_ext not in self.config.allowed_extensions:
                return False, f"File type '{file_ext}' not allowed. Allowed types: {self.config.allowed_extensions}"
            
            # Basic security scan - check for suspicious content
            if self._scan_file_security(file_path):
                return False, "File failed security scan"
            
            logger.info(f"File validation passed: {file_path}")
            return True, ""
            
        except Exception as e:
            logger.error(f"File validation error: {str(e)}")
            return False, f"Validation error: {str(e)}"
    
    def _scan_file_security(self, file_path: str) -> bool:
        """Basic security scan of file content.
        
        Args:
            file_path: Path to the file to scan
            
        Returns:
            True if suspicious content found, False otherwise
        """
        try:
            # List of suspicious patterns (basic implementation)
            suspicious_patterns = [
                b'<script',
                b'javascript:',
                b'vbscript:',
                b'onload=',
                b'onerror=',
                b'eval(',
                b'exec(',
            ]
            
            with open(file_path, 'rb') as f:
                # Read first 1MB for scanning
                chunk = f.read(1024 * 1024)
                chunk_lower = chunk.lower()
                
                for pattern in suspicious_patterns:
                    if pattern in chunk_lower:
                        logger.warning(f"Suspicious pattern found in file: {pattern.decode('utf-8', errors='ignore')}")
                        return True
            
            return False
            
        except Exception as e:
            logger.warning(f"Security scan error: {str(e)}")
            return False
    
    def _calculate_file_hash(self, file_path: str, algorithm: str = 'sha256') -> str:
        """Calculate file hash for integrity verification.
        
        Args:
            file_path: Path to the file
            algorithm: Hash algorithm to use
            
        Returns:
            Hex digest of the file hash
        """
        hash_obj = hashlib.new(algorithm)
        
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                hash_obj.update(chunk)
        
        return hash_obj.hexdigest()
    
    def _generate_s3_key(self, file_path: str, prefix: str = "uploads") -> str:
        """Generate S3 key with proper structure.
        
        Args:
            file_path: Original file path
            prefix: S3 key prefix
            
        Returns:
            Generated S3 key
        """
        file_name = Path(file_path).name
        timestamp = datetime.now().strftime("%Y/%m/%d")
        unique_id = hashlib.md5(f"{file_name}{datetime.now().isoformat()}".encode()).hexdigest()[:8]
        
        return f"{prefix}/{timestamp}/{unique_id}_{file_name}"
    
    def upload_file(
        self,
        file_path: str,
        s3_key: Optional[str] = None,
        metadata: Optional[Dict[str, str]] = None,
        tags: Optional[Dict[str, str]] = None
    ) -> Dict[str, any]:
        """Upload file to S3 using secure multipart upload.
        
        Args:
            file_path: Path to the file to upload
            s3_key: S3 object key (auto-generated if not provided)
            metadata: Optional metadata to attach to the object
            tags: Optional tags to attach to the object
            
        Returns:
            Upload result dictionary
        """
        start_time = datetime.now()
        
        try:
            # Validate file
            is_valid, error_msg = self._validate_file(file_path)
            if not is_valid:
                raise ValueError(error_msg)
            
            # Generate S3 key if not provided
            if not s3_key:
                s3_key = self._generate_s3_key(file_path)
            
            # Calculate file hash for integrity
            file_hash = self._calculate_file_hash(file_path)
            file_size = Path(file_path).stat().st_size
            
            # Prepare metadata
            upload_metadata = {
                'uploaded-by': os.environ.get('USER', 'unknown'),
                'upload-timestamp': datetime.now().isoformat(),
                'file-hash-sha256': file_hash,
                'original-filename': Path(file_path).name,
                'upload-method': 'secure-multipart'
            }
            
            if metadata:
                upload_metadata.update(metadata)
            
            # Prepare tags
            upload_tags = {
                'Environment': os.environ.get('ENVIRONMENT', 'dev'),
                'Project': 'secure-upload-system',
                'Encrypted': 'true'
            }
            
            if tags:
                upload_tags.update(tags)
            
            # Convert tags to S3 format
            tag_set = [{'Key': k, 'Value': v} for k, v in upload_tags.items()]
            
            logger.info(f"Starting secure upload: {file_path} -> s3://{self.config.bucket_name}/{s3_key}")
            
            # Determine upload method based on file size
            if file_size <= self.config.multipart_threshold:
                result = self._upload_single_part(
                    file_path, s3_key, upload_metadata, tag_set
                )
            else:
                result = self._upload_multipart(
                    file_path, s3_key, upload_metadata, tag_set
                )
            
            # Calculate upload duration
            duration = (datetime.now() - start_time).total_seconds()
            
            # Prepare result
            upload_result = {
                'success': True,
                'bucket': self.config.bucket_name,
                's3_key': s3_key,
                'file_path': file_path,
                'file_size': file_size,
                'file_hash': file_hash,
                'upload_duration': duration,
                'upload_speed_mbps': (file_size / (1024 * 1024)) / max(duration, 1),
                'etag': result.get('ETag', ''),
                'version_id': result.get('VersionId', ''),
                'metadata': upload_metadata,
                'tags': upload_tags
            }
            
            logger.info(f"Upload completed successfully: {s3_key} ({file_size:,} bytes in {duration:.2f}s)")
            
            return upload_result
            
        except Exception as e:
            logger.error(f"Upload failed: {str(e)}")
            return {
                'success': False,
                'error': str(e),
                'file_path': file_path,
                's3_key': s3_key
            }
    
    def _upload_single_part(
        self,
        file_path: str,
        s3_key: str,
        metadata: Dict[str, str],
        tag_set: List[Dict[str, str]]
    ) -> Dict[str, any]:
        """Upload file as single part.
        
        Args:
            file_path: Path to the file
            s3_key: S3 object key
            metadata: Object metadata
            tag_set: Object tags
            
        Returns:
            Upload response
        """
        try:
            with open(file_path, 'rb') as f:
                response = self.s3_client.put_object(
                    Bucket=self.config.bucket_name,
                    Key=s3_key,
                    Body=f,
                    Metadata=metadata,
                    Tagging='&'.join([f"{tag['Key']}={tag['Value']}" for tag in tag_set]),
                    ServerSideEncryption='aws:kms',
                    SSEKMSKeyId=self.config.kms_key_id,
                    StorageClass='STANDARD'
                )
            
            return response
            
        except Exception as e:
            logger.error(f"Single part upload failed: {str(e)}")
            raise
    
    def _upload_multipart(
        self,
        file_path: str,
        s3_key: str,
        metadata: Dict[str, str],
        tag_set: List[Dict[str, str]]
    ) -> Dict[str, any]:
        """Upload file using multipart upload.
        
        Args:
            file_path: Path to the file
            s3_key: S3 object key
            metadata: Object metadata
            tag_set: Object tags
            
        Returns:
            Upload response
        """
        upload_id = None
        parts = []
        
        try:
            # Initiate multipart upload
            response = self.s3_client.create_multipart_upload(
                Bucket=self.config.bucket_name,
                Key=s3_key,
                Metadata=metadata,
                ServerSideEncryption='aws:kms',
                SSEKMSKeyId=self.config.kms_key_id,
                StorageClass='STANDARD',
                Tagging='&'.join([f"{tag['Key']}={tag['Value']}" for tag in tag_set])
            )
            
            upload_id = response['UploadId']
            logger.info(f"Multipart upload initiated: {upload_id}")
            
            # Calculate parts
            file_size = Path(file_path).stat().st_size
            part_size = self.config.multipart_chunksize
            num_parts = (file_size + part_size - 1) // part_size
            
            # Upload parts with progress tracking
            with tqdm(total=num_parts, desc="Uploading parts", unit="part") as pbar:
                with ThreadPoolExecutor(max_workers=self.config.max_concurrent_uploads) as executor:
                    # Submit upload tasks
                    future_to_part = {}
                    
                    with open(file_path, 'rb') as f:
                        for part_num in range(1, num_parts + 1):
                            start_byte = (part_num - 1) * part_size
                            end_byte = min(start_byte + part_size, file_size)
                            
                            f.seek(start_byte)
                            part_data = f.read(end_byte - start_byte)
                            
                            future = executor.submit(
                                self._upload_part,
                                part_data, upload_id, s3_key, part_num
                            )
                            future_to_part[future] = part_num
                    
                    # Collect results
                    for future in as_completed(future_to_part):
                        part_num = future_to_part[future]
                        try:
                            part_result = future.result()
                            parts.append(part_result)
                            pbar.update(1)
                        except Exception as e:
                            logger.error(f"Part {part_num} upload failed: {str(e)}")
                            raise
            
            # Sort parts by part number
            parts.sort(key=lambda x: x['PartNumber'])
            
            # Complete multipart upload
            response = self.s3_client.complete_multipart_upload(
                Bucket=self.config.bucket_name,
                Key=s3_key,
                UploadId=upload_id,
                MultipartUpload={'Parts': parts}
            )
            
            logger.info(f"Multipart upload completed: {s3_key}")
            return response
            
        except Exception as e:
            # Abort multipart upload on error
            if upload_id:
                try:
                    self.s3_client.abort_multipart_upload(
                        Bucket=self.config.bucket_name,
                        Key=s3_key,
                        UploadId=upload_id
                    )
                    logger.info(f"Aborted multipart upload: {upload_id}")
                except Exception as abort_error:
                    logger.error(f"Failed to abort multipart upload: {str(abort_error)}")
            
            logger.error(f"Multipart upload failed: {str(e)}")
            raise
    
    def _upload_part(self, part_data: bytes, upload_id: str, s3_key: str, part_number: int) -> Dict[str, any]:
        """Upload a single part of multipart upload.
        
        Args:
            part_data: Part data bytes
            upload_id: Multipart upload ID
            s3_key: S3 object key
            part_number: Part number
            
        Returns:
            Part upload result
        """
        try:
            response = self.s3_client.upload_part(
                Bucket=self.config.bucket_name,
                Key=s3_key,
                PartNumber=part_number,
                UploadId=upload_id,
                Body=part_data
            )
            
            return {
                'ETag': response['ETag'],
                'PartNumber': part_number
            }
            
        except Exception as e:
            logger.error(f"Part {part_number} upload error: {str(e)}")
            raise
    
    def list_uploads(self, prefix: str = "uploads/") -> List[Dict[str, any]]:
        """List objects in the bucket with given prefix.
        
        Args:
            prefix: S3 key prefix to filter objects
            
        Returns:
            List of object information dictionaries
        """
        try:
            objects = []
            paginator = self.s3_client.get_paginator('list_objects_v2')
            
            for page in paginator.paginate(Bucket=self.config.bucket_name, Prefix=prefix):
                if 'Contents' in page:
                    for obj in page['Contents']:
                        # Get object metadata
                        try:
                            metadata_response = self.s3_client.head_object(
                                Bucket=self.config.bucket_name,
                                Key=obj['Key']
                            )
                            
                            objects.append({
                                'key': obj['Key'],
                                'size': obj['Size'],
                                'last_modified': obj['LastModified'].isoformat(),
                                'etag': obj['ETag'],
                                'storage_class': obj.get('StorageClass', 'STANDARD'),
                                'metadata': metadata_response.get('Metadata', {}),
                                'encryption': metadata_response.get('ServerSideEncryption', 'None'),
                                'kms_key_id': metadata_response.get('SSEKMSKeyId', '')
                            })
                        except Exception as e:
                            logger.warning(f"Failed to get metadata for {obj['Key']}: {str(e)}")
                            objects.append({
                                'key': obj['Key'],
                                'size': obj['Size'],
                                'last_modified': obj['LastModified'].isoformat(),
                                'etag': obj['ETag'],
                                'error': str(e)
                            })
            
            return objects
            
        except Exception as e:
            logger.error(f"Failed to list uploads: {str(e)}")
            raise


# CLI interface
@click.command()
@click.option('--file', '-f', required=True, help='File path to upload')
@click.option('--bucket', '-b', help='S3 bucket name (overrides config)')
@click.option('--key', '-k', help='S3 object key (auto-generated if not provided)')
@click.option('--role-arn', help='IAM role ARN to assume for upload')
@click.option('--config-file', '-c', default='config/upload_config.json', help='Configuration file path')
@click.option('--metadata', '-m', help='Additional metadata as JSON string')
@click.option('--tags', '-t', help='Additional tags as JSON string')
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose logging')
@click.option('--list-uploads', '-l', is_flag=True, help='List existing uploads')
def main(file, bucket, key, role_arn, config_file, metadata, tags, verbose, list_uploads):
    """Secure AWS S3 multipart upload system."""
    
    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    try:
        # Load configuration
        config_path = Path(config_file)
        if config_path.exists():
            with open(config_path, 'r') as f:
                config_data = json.load(f)
        else:
            # Default configuration
            config_data = {
                'bucket_name': os.environ.get('S3_BUCKET_NAME', ''),
                'kms_key_id': os.environ.get('KMS_KEY_ID', ''),
                'region': os.environ.get('AWS_REGION', 'us-east-1')
            }
        
        # Override with command line options
        if bucket:
            config_data['bucket_name'] = bucket
        
        if not config_data.get('bucket_name'):
            logger.error("S3 bucket name not specified")
            sys.exit(1)
        
        if not config_data.get('kms_key_id'):
            logger.error("KMS key ID not specified")
            sys.exit(1)
        
        # Create upload configuration
        upload_config = UploadConfig(**config_data)
        
        # Create upload manager
        upload_manager = SecureUploadManager(upload_config, role_arn)
        
        if list_uploads:
            # List existing uploads
            logger.info("Listing existing uploads...")
            uploads = upload_manager.list_uploads()
            
            if uploads:
                print(f"\nFound {len(uploads)} uploaded objects:")
                print("-" * 80)
                for upload in uploads:
                    size_mb = upload['size'] / (1024 * 1024)
                    print(f"Key: {upload['key']}")
                    print(f"Size: {size_mb:.2f} MB")
                    print(f"Last Modified: {upload['last_modified']}")
                    print(f"Encryption: {upload.get('encryption', 'None')}")
                    print("-" * 80)
            else:
                print("No uploads found")
            
            return
        
        # Parse additional metadata and tags
        additional_metadata = {}
        additional_tags = {}
        
        if metadata:
            try:
                additional_metadata = json.loads(metadata)
            except json.JSONDecodeError as e:
                logger.error(f"Invalid metadata JSON: {str(e)}")
                sys.exit(1)
        
        if tags:
            try:
                additional_tags = json.loads(tags)
            except json.JSONDecodeError as e:
                logger.error(f"Invalid tags JSON: {str(e)}")
                sys.exit(1)
        
        # Perform upload
        result = upload_manager.upload_file(
            file, key, additional_metadata, additional_tags
        )
        
        if result['success']:
            print(f"\n✓ Upload successful!")
            print(f"File: {result['file_path']}")
            print(f"S3 Location: s3://{result['bucket']}/{result['s3_key']}")
            print(f"Size: {result['file_size']:,} bytes")
            print(f"Duration: {result['upload_duration']:.2f} seconds")
            print(f"Speed: {result['upload_speed_mbps']:.2f} MB/s")
            print(f"SHA256: {result['file_hash']}")
        else:
            print(f"\n✗ Upload failed: {result['error']}")
            sys.exit(1)
        
    except KeyboardInterrupt:
        logger.info("Upload cancelled by user")
        sys.exit(130)
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        sys.exit(1)


if __name__ == '__main__':
    main()
