#!/usr/bin/env python3
"""
Compliance Audit Framework
Reduces audit time through automated checks and reporting
"""

import json
import csv
import os
import subprocess
import platform
import hashlib
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import List, Dict, Any
import re

@dataclass
class AuditFinding:
    """Represents a single audit finding"""
    category: str
    check_name: str
    status: str  # PASS, FAIL, WARNING, INFO
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    details: str
    remediation: str
    timestamp: str
    
class ComplianceAuditor:
    """Main audit framework class"""
    
    def __init__(self, output_dir="audit_reports"):
        self.findings: List[AuditFinding] = []
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.start_time = datetime.now()
        self.system = platform.system()
        
    def add_finding(self, category: str, check_name: str, status: str, 
                    severity: str, details: str, remediation: str = ""):
        """Add a finding to the audit results"""
        finding = AuditFinding(
            category=category,
            check_name=check_name,
            status=status,
            severity=severity,
            details=details,
            remediation=remediation,
            timestamp=datetime.now().isoformat()
        )
        self.findings.append(finding)
        
    def check_password_policy(self):
        """Check password policy compliance"""
        category = "Access Control"
        
        if self.system == "Linux":
            try:
                # Check password aging
                with open('/etc/login.defs', 'r') as f:
                    content = f.read()
                    
                max_days = re.search(r'PASS_MAX_DAYS\s+(\d+)', content)
                min_days = re.search(r'PASS_MIN_DAYS\s+(\d+)', content)
                
                if max_days and int(max_days.group(1)) <= 90:
                    self.add_finding(category, "Password Max Age", "PASS", "MEDIUM",
                                   f"Password max age: {max_days.group(1)} days")
                else:
                    self.add_finding(category, "Password Max Age", "FAIL", "HIGH",
                                   f"Password max age exceeds 90 days",
                                   "Set PASS_MAX_DAYS to 90 or less in /etc/login.defs")
            except Exception as e:
                self.add_finding(category, "Password Policy Check", "WARNING", "LOW",
                               f"Could not verify password policy: {str(e)}")
                               
    def check_file_permissions(self, critical_paths: List[str]):
        """Check file permissions on critical system files"""
        category = "File System Security"
        
        for path in critical_paths:
            if os.path.exists(path):
                stat_info = os.stat(path)
                mode = oct(stat_info.st_mode)[-3:]
                
                # Check if world-writable
                if int(mode[2]) & 2:
                    self.add_finding(category, f"File Permissions: {path}", "FAIL", 
                                   "CRITICAL",
                                   f"{path} is world-writable (mode: {mode})",
                                   f"chmod o-w {path}")
                else:
                    self.add_finding(category, f"File Permissions: {path}", "PASS", 
                                   "LOW", f"Permissions OK (mode: {mode})")
            else:
                self.add_finding(category, f"File Existence: {path}", "WARNING", 
                               "MEDIUM", f"File not found: {path}")
                               
    def check_running_services(self, prohibited_services: List[str]):
        """Check for prohibited or unnecessary services"""
        category = "Service Management"
        
        try:
            if self.system == "Linux":
                result = subprocess.run(['systemctl', 'list-units', '--type=service', 
                                       '--state=running'], 
                                      capture_output=True, text=True)
                running = result.stdout
                
                for service in prohibited_services:
                    if service in running:
                        self.add_finding(category, f"Service Check: {service}", "FAIL",
                                       "HIGH", f"Prohibited service {service} is running",
                                       f"systemctl stop {service} && systemctl disable {service}")
                    else:
                        self.add_finding(category, f"Service Check: {service}", "PASS",
                                       "LOW", f"Service {service} is not running")
                                       
            elif self.system == "Windows":
                result = subprocess.run(['powershell', '-Command', 
                                       'Get-Service | Where-Object {$_.Status -eq "Running"} | Select-Object -ExpandProperty Name'],
                                      capture_output=True, text=True)
                running_services = result.stdout.split('\n')
                
                for service in prohibited_services:
                    if service in running_services:
                        self.add_finding(category, f"Service Check: {service}", "FAIL",
                                       "HIGH", f"Prohibited service {service} is running",
                                       f"Stop-Service {service}; Set-Service {service} -StartupType Disabled")
        except Exception as e:
            self.add_finding(category, "Service Check", "WARNING", "LOW",
                           f"Could not check services: {str(e)}")
                           
    def check_firewall_status(self):
        """Verify firewall is enabled"""
        category = "Network Security"
        
        try:
            if self.system == "Linux":
                # Check ufw
                result = subprocess.run(['ufw', 'status'], capture_output=True, text=True)
                if 'Status: active' in result.stdout:
                    self.add_finding(category, "Firewall Status", "PASS", "HIGH",
                                   "UFW firewall is active")
                else:
                    self.add_finding(category, "Firewall Status", "FAIL", "CRITICAL",
                                   "UFW firewall is not active", "ufw enable")
            elif self.system == "Windows":
                result = subprocess.run(['powershell', '-Command',
                                       'Get-NetFirewallProfile | Select-Object Name,Enabled'],
                                      capture_output=True, text=True)
                if 'False' in result.stdout:
                    self.add_finding(category, "Firewall Status", "FAIL", "CRITICAL",
                                   "Windows Firewall has disabled profiles",
                                   "Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True")
                else:
                    self.add_finding(category, "Firewall Status", "PASS", "HIGH",
                                   "Windows Firewall is enabled")
        except Exception as e:
            self.add_finding(category, "Firewall Check", "WARNING", "MEDIUM",
                           f"Could not verify firewall: {str(e)}")
                           
    def check_software_inventory(self, required_software: Dict[str, str]):
        """Verify required software is installed with correct versions"""
        category = "Software Compliance"
        
        for software, min_version in required_software.items():
            # This is a simplified check - extend for your environment
            self.add_finding(category, f"Software: {software}", "INFO", "LOW",
                           f"Manual verification required for {software} >= {min_version}")
                           
    def generate_summary(self) -> Dict[str, Any]:
        """Generate audit summary statistics"""
        total = len(self.findings)
        by_status = {}
        by_severity = {}
        
        for finding in self.findings:
            by_status[finding.status] = by_status.get(finding.status, 0) + 1
            if finding.status == "FAIL":
                by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1
                
        return {
            "total_checks": total,
            "by_status": by_status,
            "failures_by_severity": by_severity,
            "duration_seconds": (datetime.now() - self.start_time).total_seconds(),
            "timestamp": datetime.now().isoformat()
        }
        
    def export_json(self, filename="audit_results.json"):
        """Export results to JSON"""
        output = {
            "summary": self.generate_summary(),
            "findings": [asdict(f) for f in self.findings]
        }
        
        filepath = self.output_dir / filename
        with open(filepath, 'w') as f:
            json.dump(output, f, indent=2)
        print(f"JSON report saved to: {filepath}")
        
    def export_csv(self, filename="audit_results.csv"):
        """Export results to CSV"""
        filepath = self.output_dir / filename
        
        with open(filepath, 'w', newline='') as f:
            if self.findings:
                writer = csv.DictWriter(f, fieldnames=asdict(self.findings[0]).keys())
                writer.writeheader()
                for finding in self.findings:
                    writer.writerow(asdict(finding))
        print(f"CSV report saved to: {filepath}")
        
    def export_html(self, filename="audit_report.html"):
        """Export results to HTML report"""
        filepath = self.output_dir / filename
        summary = self.generate_summary()
        
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Compliance Audit Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background: #2c3e50; color: white; padding: 20px; }}
        .summary {{ background: #ecf0f1; padding: 15px; margin: 20px 0; }}
        .critical {{ background: #e74c3c; color: white; }}
        .high {{ background: #e67e22; color: white; }}
        .medium {{ background: #f39c12; }}
        .low {{ background: #3498db; color: white; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th, td {{ padding: 10px; text-align: left; border: 1px solid #ddd; }}
        th {{ background: #34495e; color: white; }}
        .pass {{ color: green; font-weight: bold; }}
        .fail {{ color: red; font-weight: bold; }}
        .warning {{ color: orange; font-weight: bold; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Compliance Audit Report</h1>
        <p>Generated: {summary['timestamp']}</p>
        <p>Duration: {summary['duration_seconds']:.2f} seconds</p>
    </div>
    
    <div class="summary">
        <h2>Summary</h2>
        <p><strong>Total Checks:</strong> {summary['total_checks']}</p>
        <p><strong>Status Breakdown:</strong> {json.dumps(summary['by_status'], indent=2)}</p>
        <p><strong>Failures by Severity:</strong> {json.dumps(summary.get('failures_by_severity', {}), indent=2)}</p>
    </div>
    
    <h2>Detailed Findings</h2>
    <table>
        <tr>
            <th>Category</th>
            <th>Check</th>
            <th>Status</th>
            <th>Severity</th>
            <th>Details</th>
            <th>Remediation</th>
        </tr>
"""
        
        for finding in self.findings:
            status_class = finding.status.lower()
            severity_class = finding.severity.lower()
            html += f"""
        <tr class="{severity_class}">
            <td>{finding.category}</td>
            <td>{finding.check_name}</td>
            <td class="{status_class}">{finding.status}</td>
            <td>{finding.severity}</td>
            <td>{finding.details}</td>
            <td>{finding.remediation}</td>
        </tr>
"""
        
        html += """
    </table>
</body>
</html>
"""
        
        with open(filepath, 'w') as f:
            f.write(html)
        print(f"HTML report saved to: {filepath}")

# Example usage
def main():
    auditor = ComplianceAuditor()
    
    # Run various compliance checks
    auditor.check_password_policy()
    
    # Check critical file permissions
    critical_files = ['/etc/passwd', '/etc/shadow', '/etc/ssh/sshd_config']
    auditor.check_file_permissions(critical_files)
    
    # Check for prohibited services
    prohibited = ['telnet', 'rsh', 'ftp']
    auditor.check_running_services(prohibited)
    
    # Check firewall
    auditor.check_firewall_status()
    
    # Check required software
    required_sw = {'python': '3.8', 'openssl': '1.1.1'}
    auditor.check_software_inventory(required_sw)
    
    # Export results in multiple formats
    auditor.export_json()
    auditor.export_csv()
    auditor.export_html()
    
    # Print summary
    summary = auditor.generate_summary()
    print("\n=== Audit Summary ===")
    print(json.dumps(summary, indent=2))

if __name__ == "__main__":
    main()