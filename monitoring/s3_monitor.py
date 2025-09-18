#!/usr/bin/env python3
"""
S3 Security Monitor
==================

Advanced monitoring system for S3 access logs to detect unauthorized access
attempts and security anomalies.

Features:
- Real-time S3 access log analysis
- Unauthorized access detection
- Security anomaly alerting
- Geographic access analysis
- Suspicious pattern detection
- Automated threat response
- Compliance reporting

Author: Andy Amponsah
Version: 1.0.0
"""

import os
import sys
import json
import re
import csv
import gzip
import logging
import argparse
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Set
from dataclasses import dataclass, asdict
from collections import defaultdict, Counter
import ipaddress

import boto3
import click
import pandas as pd
import numpy as np
from botocore.exceptions import ClientError
from tabulate import tabulate
import schedule
import time

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/s3_monitor.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

@dataclass
class S3AccessLogEntry:
    """S3 access log entry data structure."""
    bucket_owner: str
    bucket_name: str
    timestamp: datetime
    remote_ip: str
    requester: str
    request_id: str
    operation: str
    key: str
    request_uri: str
    http_status: int
    error_code: str
    bytes_sent: int
    object_size: int
    total_time: int
    turn_around_time: int
    referer: str
    user_agent: str
    version_id: str
    host_id: str
    signature_version: str
    cipher_suite: str
    authentication_type: str
    host_header: str
    tls_version: str

@dataclass
class SecurityAlert:
    """Security alert data structure."""
    alert_id: str
    timestamp: datetime
    severity: str  # HIGH, MEDIUM, LOW
    category: str  # UNAUTHORIZED_ACCESS, SUSPICIOUS_PATTERN, etc.
    description: str
    source_ip: str
    user_agent: str
    operation: str
    resource: str
    details: Dict[str, any]
    
class S3SecurityMonitor:
    """Advanced S3 security monitoring system."""
    
    def __init__(self, bucket_name: str, access_logs_bucket: str, region: str = "us-east-1"):
        """Initialize the S3 security monitor.
        
        Args:
            bucket_name: Name of the S3 bucket to monitor
            access_logs_bucket: Bucket containing access logs
            region: AWS region
        """
        self.bucket_name = bucket_name
        self.access_logs_bucket = access_logs_bucket
        self.region = region
        self.alerts = []
        self.whitelist_ips = set()
        self.known_user_agents = set()
        
        # Initialize AWS clients
        self.s3_client = boto3.client('s3', region_name=region)
        self.sns_client = boto3.client('sns', region_name=region)
        self.cloudwatch_client = boto3.client('cloudwatch', region_name=region)
        
        # Load configuration
        self._load_configuration()
        
    def _load_configuration(self):
        """Load monitoring configuration."""
        try:
            config_file = Path('config/monitor_config.json')
            if config_file.exists():
                with open(config_file, 'r') as f:
                    config = json.load(f)
                    
                self.whitelist_ips = set(config.get('whitelist_ips', []))
                self.known_user_agents = set(config.get('known_user_agents', []))
                self.alert_thresholds = config.get('alert_thresholds', {
                    'failed_requests_per_minute': 10,
                    'requests_per_ip_per_minute': 100,
                    'unusual_user_agents': 5,
                    'geographic_anomaly_threshold': 0.1
                })
                
                logger.info("Monitoring configuration loaded")
            else:
                # Default configuration
                self.alert_thresholds = {
                    'failed_requests_per_minute': 10,
                    'requests_per_ip_per_minute': 100,
                    'unusual_user_agents': 5,
                    'geographic_anomaly_threshold': 0.1
                }
                logger.warning("Using default monitoring configuration")
                
        except Exception as e:
            logger.error(f"Failed to load configuration: {str(e)}")
            raise
    
    def parse_s3_access_log_line(self, log_line: str) -> Optional[S3AccessLogEntry]:
        """Parse a single S3 access log line.
        
        Args:
            log_line: Raw log line from S3 access log
            
        Returns:
            Parsed S3AccessLogEntry or None if parsing fails
        """
        try:
            # S3 access log format (space-separated with quoted strings)
            # Pattern to match quoted and unquoted fields
            pattern = r'(?:[^\\s\"]+|\"(?:[^\\\"]|\\\\.)*\")'
            fields = re.findall(pattern, log_line.strip())
            
            # Remove quotes from quoted fields
            fields = [field.strip('\"') if field.startswith('\"') else field for field in fields]
            
            if len(fields) < 24:
                logger.warning(f"Incomplete log line: {log_line[:100]}...")
                return None
            
            # Parse timestamp
            timestamp_str = f"{fields[2]} {fields[3]}"
            timestamp = datetime.strptime(timestamp_str, "[%d/%b/%Y:%H:%M:%S %z]")
            
            entry = S3AccessLogEntry(
                bucket_owner=fields[0],
                bucket_name=fields[1],
                timestamp=timestamp,
                remote_ip=fields[4],
                requester=fields[5],
                request_id=fields[6],
                operation=fields[7],
                key=fields[8],
                request_uri=fields[9],
                http_status=int(fields[10]) if fields[10] != '-' else 0,
                error_code=fields[11],
                bytes_sent=int(fields[12]) if fields[12] != '-' else 0,
                object_size=int(fields[13]) if fields[13] != '-' else 0,
                total_time=int(fields[14]) if fields[14] != '-' else 0,
                turn_around_time=int(fields[15]) if fields[15] != '-' else 0,
                referer=fields[16],
                user_agent=fields[17],
                version_id=fields[18],
                host_id=fields[19],
                signature_version=fields[20],
                cipher_suite=fields[21],
                authentication_type=fields[22],
                host_header=fields[23],
                tls_version=fields[24] if len(fields) > 24 else ''
            )
            
            return entry
            
        except Exception as e:
            logger.warning(f"Failed to parse log line: {str(e)}")
            return None
    
    def fetch_access_logs(self, start_date: datetime, end_date: datetime) -> List[S3AccessLogEntry]:
        """Fetch and parse S3 access logs for the specified time range.
        
        Args:
            start_date: Start date for log analysis
            end_date: End date for log analysis
            
        Returns:
            List of parsed S3AccessLogEntry objects
        """
        log_entries = []
        
        try:
            # List log files in the access logs bucket
            paginator = self.s3_client.get_paginator('list_objects_v2')
            
            for page in paginator.paginate(
                Bucket=self.access_logs_bucket,
                Prefix='access-logs/'
            ):
                if 'Contents' not in page:
                    continue
                
                for obj in page['Contents']:
                    # Filter by date based on object key
                    obj_date = self._extract_date_from_key(obj['Key'])
                    if obj_date and start_date <= obj_date <= end_date:
                        # Download and process log file
                        entries = self._process_log_file(obj['Key'])
                        log_entries.extend(entries)
            
            logger.info(f"Fetched {len(log_entries)} log entries")
            return log_entries
            
        except Exception as e:
            logger.error(f"Failed to fetch access logs: {str(e)}")
            return []
    
    def _extract_date_from_key(self, key: str) -> Optional[datetime]:
        """Extract date from S3 object key.
        
        Args:
            key: S3 object key
            
        Returns:
            Extracted date or None
        """
        try:
            # Extract date pattern from key (YYYY-MM-DD format)
            date_match = re.search(r'(\\d{4})-(\\d{2})-(\\d{2})', key)
            if date_match:
                year, month, day = map(int, date_match.groups())
                return datetime(year, month, day)
            return None
        except Exception:
            return None
    
    def _process_log_file(self, key: str) -> List[S3AccessLogEntry]:
        """Process a single log file from S3.
        
        Args:
            key: S3 object key for the log file
            
        Returns:
            List of parsed log entries
        """
        entries = []
        
        try:
            # Download log file
            response = self.s3_client.get_object(
                Bucket=self.access_logs_bucket,
                Key=key
            )
            
            content = response['Body'].read()
            
            # Handle gzipped files
            if key.endswith('.gz'):
                content = gzip.decompress(content)
            
            # Parse log lines
            log_content = content.decode('utf-8', errors='ignore')
            for line in log_content.split('\\n'):
                if line.strip():
                    entry = self.parse_s3_access_log_line(line)
                    if entry:
                        entries.append(entry)
            
            logger.debug(f"Processed {len(entries)} entries from {key}")
            
        except Exception as e:
            logger.warning(f"Failed to process log file {key}: {str(e)}")
        
        return entries
    
    def analyze_security_threats(self, log_entries: List[S3AccessLogEntry]) -> List[SecurityAlert]:
        """Analyze log entries for security threats.
        
        Args:
            log_entries: List of S3 access log entries
            
        Returns:
            List of security alerts
        """
        alerts = []
        
        # Group entries by time windows for analysis
        time_windows = self._group_by_time_windows(log_entries, window_minutes=1)
        
        for window_time, entries in time_windows.items():
            # Analyze each time window
            window_alerts = []
            
            # Check for excessive failed requests
            window_alerts.extend(self._detect_excessive_failed_requests(entries, window_time))
            
            # Check for suspicious IP patterns
            window_alerts.extend(self._detect_suspicious_ip_patterns(entries, window_time))
            
            # Check for unusual user agents
            window_alerts.extend(self._detect_unusual_user_agents(entries, window_time))
            
            # Check for unauthorized operations
            window_alerts.extend(self._detect_unauthorized_operations(entries, window_time))
            
            # Check for geographic anomalies
            window_alerts.extend(self._detect_geographic_anomalies(entries, window_time))
            
            alerts.extend(window_alerts)
        
        # Sort alerts by severity and timestamp
        alerts.sort(key=lambda x: (x.severity, x.timestamp), reverse=True)
        
        logger.info(f"Generated {len(alerts)} security alerts")
        return alerts
    
    def _group_by_time_windows(self, log_entries: List[S3AccessLogEntry], window_minutes: int) -> Dict[datetime, List[S3AccessLogEntry]]:
        """Group log entries by time windows.
        
        Args:
            log_entries: List of log entries
            window_minutes: Time window size in minutes
            
        Returns:
            Dictionary mapping time windows to log entries
        """
        windows = defaultdict(list)
        
        for entry in log_entries:
            # Round timestamp to window boundary
            window_time = entry.timestamp.replace(
                minute=entry.timestamp.minute // window_minutes * window_minutes,
                second=0,
                microsecond=0
            )
            windows[window_time].append(entry)
        
        return dict(windows)
    
    def _detect_excessive_failed_requests(self, entries: List[S3AccessLogEntry], window_time: datetime) -> List[SecurityAlert]:
        """Detect excessive failed requests in time window.
        
        Args:
            entries: Log entries for the time window
            window_time: Time window timestamp
            
        Returns:
            List of security alerts
        """
        alerts = []
        
        # Count failed requests (4xx and 5xx status codes)
        failed_requests = [e for e in entries if 400 <= e.http_status < 600]
        
        if len(failed_requests) > self.alert_thresholds['failed_requests_per_minute']:
            # Group by IP to identify sources
            ip_failures = defaultdict(list)
            for entry in failed_requests:
                ip_failures[entry.remote_ip].append(entry)
            
            for ip, failures in ip_failures.items():
                if len(failures) >= 5:  # Threshold for individual IP
                    alert = SecurityAlert(
                        alert_id=f"excessive_failures_{ip}_{window_time.strftime('%Y%m%d_%H%M')}",
                        timestamp=window_time,
                        severity="HIGH",
                        category="EXCESSIVE_FAILED_REQUESTS",
                        description=f"Excessive failed requests from IP {ip}",
                        source_ip=ip,
                        user_agent=failures[0].user_agent,
                        operation="MULTIPLE",
                        resource=self.bucket_name,
                        details={
                            "failed_requests_count": len(failures),
                            "status_codes": list(set(f.http_status for f in failures)),
                            "operations": list(set(f.operation for f in failures))
                        }
                    )
                    alerts.append(alert)
        
        return alerts
    
    def _detect_suspicious_ip_patterns(self, entries: List[S3AccessLogEntry], window_time: datetime) -> List[SecurityAlert]:
        """Detect suspicious IP access patterns.
        
        Args:
            entries: Log entries for the time window
            window_time: Time window timestamp
            
        Returns:
            List of security alerts
        """
        alerts = []
        
        # Group requests by IP
        ip_requests = defaultdict(list)
        for entry in entries:
            ip_requests[entry.remote_ip].append(entry)
        
        for ip, requests in ip_requests.items():
            # Skip whitelisted IPs
            if ip in self.whitelist_ips:
                continue
            
            # Check for excessive requests per IP
            if len(requests) > self.alert_thresholds['requests_per_ip_per_minute']:
                alert = SecurityAlert(
                    alert_id=f"excessive_requests_{ip}_{window_time.strftime('%Y%m%d_%H%M')}",
                    timestamp=window_time,
                    severity="MEDIUM",
                    category="EXCESSIVE_REQUESTS_PER_IP",
                    description=f"Excessive requests from IP {ip}",
                    source_ip=ip,
                    user_agent=requests[0].user_agent,
                    operation="MULTIPLE",
                    resource=self.bucket_name,
                    details={
                        "request_count": len(requests),
                        "unique_operations": len(set(r.operation for r in requests)),
                        "unique_resources": len(set(r.key for r in requests))
                    }
                )
                alerts.append(alert)
            
            # Check for scanning behavior (accessing many different resources)
            unique_keys = set(r.key for r in requests if r.key != '-')
            if len(unique_keys) > 50:  # Threshold for scanning
                alert = SecurityAlert(
                    alert_id=f"scanning_behavior_{ip}_{window_time.strftime('%Y%m%d_%H%M')}",
                    timestamp=window_time,
                    severity="HIGH",
                    category="SCANNING_BEHAVIOR",
                    description=f"Potential scanning behavior from IP {ip}",
                    source_ip=ip,
                    user_agent=requests[0].user_agent,
                    operation="SCAN",
                    resource=self.bucket_name,
                    details={
                        "unique_resources_accessed": len(unique_keys),
                        "total_requests": len(requests)
                    }
                )
                alerts.append(alert)
        
        return alerts
    
    def _detect_unusual_user_agents(self, entries: List[S3AccessLogEntry], window_time: datetime) -> List[SecurityAlert]:
        """Detect unusual user agent patterns.
        
        Args:
            entries: Log entries for the time window
            window_time: Time window timestamp
            
        Returns:
            List of security alerts
        """
        alerts = []
        
        # Analyze user agents
        user_agent_patterns = Counter(entry.user_agent for entry in entries)
        
        for user_agent, count in user_agent_patterns.items():
            # Skip known user agents
            if user_agent in self.known_user_agents:
                continue
            
            # Check for suspicious patterns
            suspicious_indicators = [
                'bot', 'spider', 'crawler', 'scanner', 'exploit',
                'sqlmap', 'nikto', 'dirb', 'gobuster', 'dirbuster'
            ]
            
            user_agent_lower = user_agent.lower()
            
            if any(indicator in user_agent_lower for indicator in suspicious_indicators):
                # Find IPs using this user agent
                ips_with_ua = set(e.remote_ip for e in entries if e.user_agent == user_agent)
                
                alert = SecurityAlert(
                    alert_id=f"suspicious_user_agent_{hash(user_agent)}_{window_time.strftime('%Y%m%d_%H%M')}",
                    timestamp=window_time,
                    severity="MEDIUM",
                    category="SUSPICIOUS_USER_AGENT",
                    description=f"Suspicious user agent detected: {user_agent[:100]}",
                    source_ip=list(ips_with_ua)[0] if ips_with_ua else "unknown",
                    user_agent=user_agent,
                    operation="MULTIPLE",
                    resource=self.bucket_name,
                    details={
                        "user_agent": user_agent,
                        "request_count": count,
                        "source_ips": list(ips_with_ua)
                    }
                )
                alerts.append(alert)
        
        return alerts
    
    def _detect_unauthorized_operations(self, entries: List[S3AccessLogEntry], window_time: datetime) -> List[SecurityAlert]:
        """Detect unauthorized operations.
        
        Args:
            entries: Log entries for the time window
            window_time: Time window timestamp
            
        Returns:
            List of security alerts
        """
        alerts = []
        
        # Define sensitive operations
        sensitive_operations = [
            'REST.DELETE.OBJECT',
            'REST.PUT.BUCKET',
            'REST.DELETE.BUCKET',
            'REST.PUT.BUCKETPOLICY',
            'REST.PUT.BUCKETACL',
            'REST.PUT.OBJECTACL'
        ]
        
        for entry in entries:
            if entry.operation in sensitive_operations:
                # Check if the operation failed (might indicate unauthorized attempt)
                if entry.http_status >= 400:
                    alert = SecurityAlert(
                        alert_id=f"unauthorized_operation_{entry.request_id}",
                        timestamp=entry.timestamp,
                        severity="HIGH",
                        category="UNAUTHORIZED_OPERATION",
                        description=f"Failed {entry.operation} operation",
                        source_ip=entry.remote_ip,
                        user_agent=entry.user_agent,
                        operation=entry.operation,
                        resource=entry.key,
                        details={
                            "http_status": entry.http_status,
                            "error_code": entry.error_code,
                            "requester": entry.requester
                        }
                    )
                    alerts.append(alert)
        
        return alerts
    
    def _detect_geographic_anomalies(self, entries: List[S3AccessLogEntry], window_time: datetime) -> List[SecurityAlert]:
        """Detect geographic anomalies in access patterns.
        
        Args:
            entries: Log entries for the time window
            window_time: Time window timestamp
            
        Returns:
            List of security alerts
        """
        alerts = []
        
        # This is a simplified implementation
        # In production, this would integrate with IP geolocation services
        
        # Check for private/local IP addresses accessing from unexpected locations
        for entry in entries:
            try:
                ip_obj = ipaddress.ip_address(entry.remote_ip)
                
                # Alert on local/private IPs if they shouldn't have access
                if ip_obj.is_private and entry.remote_ip not in self.whitelist_ips:
                    alert = SecurityAlert(
                        alert_id=f"private_ip_access_{entry.remote_ip}_{window_time.strftime('%Y%m%d_%H%M')}",
                        timestamp=entry.timestamp,
                        severity="MEDIUM",
                        category="PRIVATE_IP_ACCESS",
                        description=f"Access from private IP {entry.remote_ip}",
                        source_ip=entry.remote_ip,
                        user_agent=entry.user_agent,
                        operation=entry.operation,
                        resource=entry.key,
                        details={
                            "ip_type": "private",
                            "http_status": entry.http_status
                        }
                    )
                    alerts.append(alert)
            
            except ValueError:
                # Invalid IP address
                continue
        
        return alerts
    
    def send_alert(self, alert: SecurityAlert, sns_topic_arn: Optional[str] = None):
        """Send security alert notification.
        
        Args:
            alert: Security alert to send
            sns_topic_arn: SNS topic ARN for notifications
        """
        try:
            # Log the alert
            logger.warning(f"SECURITY ALERT [{alert.severity}]: {alert.description}")
            
            # Send to CloudWatch metrics
            self._send_cloudwatch_metric(alert)
            
            # Send SNS notification if topic ARN provided
            if sns_topic_arn:
                self._send_sns_notification(alert, sns_topic_arn)
            
            # Store alert for reporting
            self.alerts.append(alert)
            
        except Exception as e:
            logger.error(f"Failed to send alert: {str(e)}")
    
    def _send_cloudwatch_metric(self, alert: SecurityAlert):
        """Send alert as CloudWatch metric.
        
        Args:
            alert: Security alert
        """
        try:
            self.cloudwatch_client.put_metric_data(
                Namespace='S3Security',
                MetricData=[
                    {
                        'MetricName': alert.category,
                        'Value': 1,
                        'Unit': 'Count',
                        'Dimensions': [
                            {
                                'Name': 'Severity',
                                'Value': alert.severity
                            },
                            {
                                'Name': 'SourceIP',
                                'Value': alert.source_ip
                            }
                        ],
                        'Timestamp': alert.timestamp
                    }
                ]
            )
        except Exception as e:
            logger.error(f"Failed to send CloudWatch metric: {str(e)}")
    
    def _send_sns_notification(self, alert: SecurityAlert, topic_arn: str):
        """Send SNS notification for alert.
        
        Args:
            alert: Security alert
            topic_arn: SNS topic ARN
        """
        try:
            message = {
                "alert_id": alert.alert_id,
                "timestamp": alert.timestamp.isoformat(),
                "severity": alert.severity,
                "category": alert.category,
                "description": alert.description,
                "source_ip": alert.source_ip,
                "user_agent": alert.user_agent,
                "operation": alert.operation,
                "resource": alert.resource,
                "details": alert.details
            }
            
            self.sns_client.publish(
                TopicArn=topic_arn,
                Subject=f"S3 Security Alert: {alert.category}",
                Message=json.dumps(message, indent=2)
            )
            
        except Exception as e:
            logger.error(f"Failed to send SNS notification: {str(e)}")
    
    def generate_security_report(self, alerts: List[SecurityAlert]) -> Dict[str, any]:
        """Generate comprehensive security report.
        
        Args:
            alerts: List of security alerts
            
        Returns:
            Security report dictionary
        """
        if not alerts:
            return {
                "summary": {
                    "total_alerts": 0,
                    "severity_breakdown": {},
                    "category_breakdown": {},
                    "top_source_ips": [],
                    "report_generated": datetime.now().isoformat()
                }
            }
        
        # Calculate statistics
        severity_counts = Counter(alert.severity for alert in alerts)
        category_counts = Counter(alert.category for alert in alerts)
        ip_counts = Counter(alert.source_ip for alert in alerts)
        
        # Top threats
        top_ips = ip_counts.most_common(10)
        
        # Timeline analysis
        alerts_by_hour = defaultdict(int)
        for alert in alerts:
            hour_key = alert.timestamp.strftime("%Y-%m-%d %H:00")
            alerts_by_hour[hour_key] += 1
        
        report = {
            "summary": {
                "total_alerts": len(alerts),
                "severity_breakdown": dict(severity_counts),
                "category_breakdown": dict(category_counts),
                "top_source_ips": [{"ip": ip, "alert_count": count} for ip, count in top_ips],
                "report_generated": datetime.now().isoformat()
            },
            "timeline": dict(alerts_by_hour),
            "detailed_alerts": [asdict(alert) for alert in alerts[:50]]  # Top 50 alerts
        }
        
        return report
    
    def run_continuous_monitoring(self, check_interval_minutes: int = 1, sns_topic_arn: Optional[str] = None):
        """Run continuous monitoring of S3 access logs.
        
        Args:
            check_interval_minutes: Interval between checks in minutes
            sns_topic_arn: SNS topic ARN for notifications
        """
        logger.info(f"Starting continuous monitoring (check interval: {check_interval_minutes} minutes)")
        
        def check_logs():
            try:
                # Analyze logs from the last check interval
                end_time = datetime.now()
                start_time = end_time - timedelta(minutes=check_interval_minutes * 2)  # Overlap for safety
                
                logger.info(f"Analyzing logs from {start_time} to {end_time}")
                
                # Fetch and analyze logs
                log_entries = self.fetch_access_logs(start_time, end_time)
                if log_entries:
                    alerts = self.analyze_security_threats(log_entries)
                    
                    # Send alerts
                    for alert in alerts:
                        self.send_alert(alert, sns_topic_arn)
                    
                    if alerts:
                        logger.info(f"Generated {len(alerts)} alerts in this check")
                else:
                    logger.info("No log entries found for analysis period")
                    
            except Exception as e:
                logger.error(f"Error in continuous monitoring: {str(e)}")
        
        # Schedule regular checks
        schedule.every(check_interval_minutes).minutes.do(check_logs)
        
        try:
            while True:
                schedule.run_pending()
                time.sleep(60)  # Check every minute
        except KeyboardInterrupt:
            logger.info("Continuous monitoring stopped by user")


# CLI interface
@click.command()
@click.option('--bucket', '-b', required=True, help='S3 bucket name to monitor')
@click.option('--logs-bucket', '-l', required=True, help='S3 bucket containing access logs')
@click.option('--start-date', '-s', help='Start date for analysis (YYYY-MM-DD)')
@click.option('--end-date', '-e', help='End date for analysis (YYYY-MM-DD)')
@click.option('--continuous', '-c', is_flag=True, help='Run continuous monitoring')
@click.option('--interval', '-i', default=1, help='Monitoring interval in minutes')
@click.option('--sns-topic', help='SNS topic ARN for alerts')
@click.option('--output-format', '-f', default='table', type=click.Choice(['table', 'json', 'csv']), help='Output format')
@click.option('--output-file', '-o', help='Output file path')
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose logging')
def main(bucket, logs_bucket, start_date, end_date, continuous, interval, sns_topic, output_format, output_file, verbose):
    """S3 Security Monitor - Advanced monitoring for S3 access logs."""
    
    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    try:
        # Initialize monitor
        monitor = S3SecurityMonitor(bucket, logs_bucket)
        
        if continuous:
            # Run continuous monitoring
            monitor.run_continuous_monitoring(interval, sns_topic)
        else:
            # One-time analysis
            if not start_date:
                start_date = (datetime.now() - timedelta(days=1)).strftime('%Y-%m-%d')
            if not end_date:
                end_date = datetime.now().strftime('%Y-%m-%d')
            
            start_dt = datetime.strptime(start_date, '%Y-%m-%d')
            end_dt = datetime.strptime(end_date, '%Y-%m-%d')
            
            logger.info(f"Analyzing logs from {start_date} to {end_date}")
            
            # Fetch and analyze logs
            log_entries = monitor.fetch_access_logs(start_dt, end_dt)
            
            if not log_entries:
                print("No log entries found for the specified time range")
                return
            
            alerts = monitor.analyze_security_threats(log_entries)
            
            # Generate report
            report = monitor.generate_security_report(alerts)
            
            # Output results
            if output_format == 'json':
                output_data = json.dumps(report, indent=2, default=str)
                if output_file:
                    with open(output_file, 'w') as f:
                        f.write(output_data)
                else:
                    print(output_data)
            
            elif output_format == 'csv':
                if alerts:
                    df = pd.DataFrame([asdict(alert) for alert in alerts])
                    if output_file:
                        df.to_csv(output_file, index=False)
                    else:
                        print(df.to_csv(index=False))
                else:
                    print("No alerts to output")
            
            else:  # table format
                print("\\n=== S3 Security Analysis Report ===")
                print(f"Analysis Period: {start_date} to {end_date}")
                print(f"Total Log Entries: {len(log_entries):,}")
                print(f"Total Alerts: {len(alerts)}")
                
                if alerts:
                    print("\\n=== Alert Summary ===")
                    severity_counts = Counter(alert.severity for alert in alerts)
                    category_counts = Counter(alert.category for alert in alerts)
                    
                    print("Severity Breakdown:")
                    for severity, count in severity_counts.items():
                        print(f"  {severity}: {count}")
                    
                    print("\\nCategory Breakdown:")
                    for category, count in category_counts.items():
                        print(f"  {category}: {count}")
                    
                    print("\\n=== Top 10 Alerts ===")
                    table_data = []
                    for alert in alerts[:10]:
                        table_data.append([
                            alert.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                            alert.severity,
                            alert.category,
                            alert.source_ip,
                            alert.description[:60] + '...' if len(alert.description) > 60 else alert.description
                        ])
                    
                    print(tabulate(
                        table_data,
                        headers=['Timestamp', 'Severity', 'Category', 'Source IP', 'Description'],
                        tablefmt='grid'
                    ))
                else:
                    print("\\n✓ No security threats detected!")
            
            # Send alerts if SNS topic provided
            if sns_topic and alerts:
                print(f"\\nSending {len(alerts)} alerts to SNS topic...")
                for alert in alerts:
                    monitor.send_alert(alert, sns_topic)
                print("Alerts sent successfully")
        
    except KeyboardInterrupt:
        logger.info("Analysis cancelled by user")
        sys.exit(130)
    except Exception as e:
        logger.error(f"Analysis failed: {str(e)}")
        sys.exit(1)


if __name__ == '__main__':
    main()
