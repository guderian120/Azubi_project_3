#!/usr/bin/env python3
"""
Test Suite for Secure Upload System
===================================

Comprehensive test suite for the secure S3 upload system.

Test Categories:
- Unit tests for core functionality
- Integration tests with AWS services
- Security validation tests
- Performance tests
- Error handling tests

Author: ANDY AMPONSAH
Version: 1.0.0
"""

import os
import sys
import json
import tempfile
import unittest
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path
import hashlib
from datetime import datetime

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from scripts.secure_upload import SecureUploadManager, UploadConfig
from monitoring.s3_monitor import S3SecurityMonitor, S3AccessLogEntry, SecurityAlert

class TestUploadConfig(unittest.TestCase):
    """Test cases for UploadConfig class."""
    
    def test_default_config(self):
        """Test default configuration values."""
        config = UploadConfig(
            bucket_name="test-bucket",
            kms_key_id="test-key-id"
        )
        
        self.assertEqual(config.bucket_name, "test-bucket")
        self.assertEqual(config.kms_key_id, "test-key-id")
        self.assertEqual(config.region, "us-east-1")
        self.assertEqual(config.multipart_threshold, 100 * 1024 * 1024)
        self.assertEqual(config.multipart_chunksize, 8 * 1024 * 1024)
        self.assertIsInstance(config.allowed_extensions, list)
        self.assertIn('.pdf', config.allowed_extensions)
    
    def test_custom_config(self):
        """Test custom configuration values."""
        config = UploadConfig(
            bucket_name="custom-bucket",
            kms_key_id="custom-key",
            region="eu-west-1",
            multipart_threshold=50 * 1024 * 1024,
            allowed_extensions=['.txt', '.csv']
        )
        
        self.assertEqual(config.region, "eu-west-1")
        self.assertEqual(config.multipart_threshold, 50 * 1024 * 1024)
        self.assertEqual(config.allowed_extensions, ['.txt', '.csv'])

class TestSecureUploadManager(unittest.TestCase):
    """Test cases for SecureUploadManager class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.config = UploadConfig(
            bucket_name="test-bucket",
            kms_key_id="test-key-id",
            region="us-east-1"
        )
        
        # Mock AWS clients
        with patch('boto3.client'):
            self.manager = SecureUploadManager(self.config)
            self.manager.s3_client = Mock()
            self.manager.kms_client = Mock()
    
    def test_file_validation_exists(self):
        """Test file validation for existing files."""
        # Create temporary test file
        with tempfile.NamedTemporaryFile(suffix='.txt', delete=False) as f:
            f.write(b"Test content")
            temp_path = f.name
        
        try:
            is_valid, error_msg = self.manager._validate_file(temp_path)
            self.assertTrue(is_valid)
            self.assertEqual(error_msg, "")
        finally:
            os.unlink(temp_path)
    
    def test_file_validation_not_exists(self):
        """Test file validation for non-existent files."""
        is_valid, error_msg = self.manager._validate_file("/non/existent/file.txt")
        self.assertFalse(is_valid)
        self.assertIn("does not exist", error_msg)
    
    def test_file_validation_size_limit(self):
        """Test file validation for size limits."""
        # Create a file that exceeds the limit
        with tempfile.NamedTemporaryFile(suffix='.txt', delete=False) as f:
            # Write data that exceeds max_file_size
            large_data = b"x" * (self.config.max_file_size + 1)
            f.write(large_data)
            temp_path = f.name
        
        try:
            is_valid, error_msg = self.manager._validate_file(temp_path)
            self.assertFalse(is_valid)
            self.assertIn("exceeds limit", error_msg)
        finally:
            os.unlink(temp_path)
    
    def test_file_validation_extension(self):
        """Test file validation for file extensions."""
        # Create file with disallowed extension
        with tempfile.NamedTemporaryFile(suffix='.exe', delete=False) as f:
            f.write(b"Test content")
            temp_path = f.name
        
        try:
            is_valid, error_msg = self.manager._validate_file(temp_path)
            self.assertFalse(is_valid)
            self.assertIn("not allowed", error_msg)
        finally:
            os.unlink(temp_path)
    
    def test_calculate_file_hash(self):
        """Test file hash calculation."""
        test_content = b"Test content for hashing"
        expected_hash = hashlib.sha256(test_content).hexdigest()
        
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(test_content)
            temp_path = f.name
        
        try:
            calculated_hash = self.manager._calculate_file_hash(temp_path)
            self.assertEqual(calculated_hash, expected_hash)
        finally:
            os.unlink(temp_path)
    
    def test_generate_s3_key(self):
        """Test S3 key generation."""
        test_path = "/path/to/test_file.txt"
        s3_key = self.manager._generate_s3_key(test_path)
        
        self.assertTrue(s3_key.startswith("uploads/"))
        self.assertTrue(s3_key.endswith("test_file.txt"))
        self.assertIn(datetime.now().strftime("%Y/%m/%d"), s3_key)
    
    def test_security_scan_clean_file(self):
        """Test security scan with clean file."""
        clean_content = b"This is clean content without any suspicious patterns"
        
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(clean_content)
            temp_path = f.name
        
        try:
            is_suspicious = self.manager._scan_file_security(temp_path)
            self.assertFalse(is_suspicious)
        finally:
            os.unlink(temp_path)
    
    def test_security_scan_suspicious_file(self):
        """Test security scan with suspicious content."""
        suspicious_content = b"<script>alert('xss')</script>"
        
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(suspicious_content)
            temp_path = f.name
        
        try:
            is_suspicious = self.manager._scan_file_security(temp_path)
            self.assertTrue(is_suspicious)
        finally:
            os.unlink(temp_path)

class TestS3SecurityMonitor(unittest.TestCase):
    """Test cases for S3SecurityMonitor class."""
    
    def setUp(self):
        """Set up test fixtures."""
        with patch('boto3.client'):
            self.monitor = S3SecurityMonitor("test-bucket", "test-logs-bucket")
            self.monitor.s3_client = Mock()
            self.monitor.sns_client = Mock()
            self.monitor.cloudwatch_client = Mock()
    
    def test_parse_s3_access_log_line(self):
        """Test parsing of S3 access log lines."""
        log_line = (
            'bucket-owner bucket [06/Feb/2023:00:00:00 +0000] 192.168.1.1 '
            'user-id 3E57427F3EXAMPLE REST.GET.OBJECT key '
            '"GET /key HTTP/1.1" 200 - 2662992 2662992 5 4 "-" '
            '"S3Console/0.4" - 79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be '
            'SigV4 ECDHE-RSA-AES128-GCM-SHA256 AuthHeader bucket.s3.amazonaws.com TLSv1.2'
        )
        
        entry = self.monitor.parse_s3_access_log_line(log_line)
        
        self.assertIsNotNone(entry)
        self.assertEqual(entry.bucket_name, "bucket")
        self.assertEqual(entry.remote_ip, "192.168.1.1")
        self.assertEqual(entry.operation, "REST.GET.OBJECT")
        self.assertEqual(entry.http_status, 200)
    
    def test_parse_invalid_log_line(self):
        """Test parsing of invalid log lines."""
        invalid_line = "incomplete log line"
        entry = self.monitor.parse_s3_access_log_line(invalid_line)
        self.assertIsNone(entry)
    
    def test_detect_excessive_failed_requests(self):
        """Test detection of excessive failed requests."""
        entries = []
        
        # 