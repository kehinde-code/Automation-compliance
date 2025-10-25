#!/usr/bin/env python3
"""
Test Suite for Compliance Audit Framework
Run this to validate the audit tool works in your environment
"""

import os
import sys
import subprocess
import platform
import json
from pathlib import Path

class AuditTester:
    def __init__(self):
        self.system = platform.system()
        self.tests_passed = 0
        self.tests_failed = 0
        self.warnings = []
        
    def print_header(self, text):
        print(f"\n{'='*60}")
        print(f"  {text}")
        print(f"{'='*60}")
        
    def test_result(self, test_name, passed, message=""):
        if passed:
            print(f"✓ {test_name}: PASS")
            self.tests_passed += 1
        else:
            print(f"✗ {test_name}: FAIL - {message}")
            self.tests_failed += 1
            
    def test_warning(self, test_name, message):
        print(f"⚠ {test_name}: WARNING - {message}")
        self.warnings.append(f"{test_name}: {message}")
        
    def test_python_version(self):
        """Test Python version compatibility"""
        version = sys.version_info
        required = (3, 6)
        
        passed = version >= required
        self.test_result(
            "Python Version",
            passed,
            f"Python {version.major}.{version.minor} found, need >= {required[0]}.{required[1]}"
        )
        return passed
        
    def test_file_system_access(self):
        """Test ability to read/write files"""
        test_dir = Path("./test_audit_output")
        
        try:
            test_dir.mkdir(exist_ok=True)
            test_file = test_dir / "test.txt"
            test_file.write_text("test")
            test_file.unlink()
            test_dir.rmdir()
            self.test_result("File System Access", True)
            return True
        except Exception as e:
            self.test_result("File System Access", False, str(e))
            return False
            
    def test_command_execution(self):
        """Test ability to execute system commands"""
        try:
            if self.system == "Linux":
                result = subprocess.run(['ls', '/etc'], 
                                      capture_output=True, 
                                      timeout=5)
            elif self.system == "Windows":
                result = subprocess.run(['cmd', '/c', 'dir'], 
                                      capture_output=True, 
                                      timeout=5)
            else:
                self.test_warning("Command Execution", f"Unknown system: {self.system}")
                return False
                
            self.test_result("Command Execution", result.returncode == 0)
            return result.returncode == 0
        except Exception as e:
            self.test_result("Command Execution", False, str(e))
            return False
            
    def test_linux_files(self):
        """Test access to Linux configuration files"""
        if self.system != "Linux":
            print("  Skipping Linux tests (not on Linux)")
            return
            
        files_to_check = [
            ("/etc/passwd", "readable", False),
            ("/etc/shadow", "readable", True),  # May need root
            ("/etc/login.defs", "readable", False),
            ("/etc/ssh/sshd_config", "readable", True),  # May need root
        ]
        
        for file_path, check_type, root_required in files_to_check:
            if os.path.exists(file_path):
                try:
                    with open(file_path, 'r') as f:
                        f.read(1)
                    self.test_result(f"Access {file_path}", True)
                except PermissionError:
                    if root_required:
                        self.test_warning(f"Access {file_path}", 
                                        "Permission denied (may need root)")
                    else:
                        self.test_result(f"Access {file_path}", False, 
                                       "Permission denied")
            else:
                self.test_warning(f"Access {file_path}", "File not found")
                
    def test_linux_commands(self):
        """Test Linux-specific commands"""
        if self.system != "Linux":
            print("  Skipping Linux command tests (not on Linux)")
            return
            
        commands = [
            ("systemctl", "--version"),
            ("ufw", "version"),
            ("ps", "--version"),
        ]
        
        for cmd, *args in commands:
            try:
                result = subprocess.run([cmd] + list(args), 
                                      capture_output=True, 
                                      timeout=5,
                                      stderr=subprocess.DEVNULL)
                if result.returncode == 0 or cmd == "ufw":  # ufw may not be installed
                    self.test_result(f"Command: {cmd}", True)
                else:
                    self.test_warning(f"Command: {cmd}", 
                                    f"Command exists but returned code {result.returncode}")
            except FileNotFoundError:
                self.test_warning(f"Command: {cmd}", 
                                "Command not found (feature will be skipped)")
            except Exception as e:
                self.test_result(f"Command: {cmd}", False, str(e))
                
    def test_windows_commands(self):
        """Test Windows-specific commands"""
        if self.system != "Windows":
            print("  Skipping Windows command tests (not on Windows)")
            return
            
        # Test PowerShell availability
        try:
            result = subprocess.run(['powershell', '-Command', 'echo test'],
                                  capture_output=True,
                                  timeout=5)
            self.test_result("PowerShell Availability", result.returncode == 0)
        except Exception as e:
            self.test_result("PowerShell Availability", False, str(e))
            
        # Test specific cmdlets (requires admin for some)
        cmdlets = [
            "Get-Service",
            "Get-NetFirewallProfile",
            "Get-LocalGroupMember -Group 'Administrators'",
        ]
        
        for cmdlet in cmdlets:
            try:
                result = subprocess.run(
                    ['powershell', '-Command', cmdlet],
                    capture_output=True,
                    timeout=10
                )
                if "PermissionDenied" in result.stderr.decode() or \
                   "Access is denied" in result.stderr.decode():
                    self.test_warning(f"Cmdlet: {cmdlet.split()[0]}", 
                                    "Permission denied (may need admin)")
                elif result.returncode == 0:
                    self.test_result(f"Cmdlet: {cmdlet.split()[0]}", True)
                else:
                    self.test_warning(f"Cmdlet: {cmdlet.split()[0]}", 
                                    f"Returned code {result.returncode}")
            except Exception as e:
                self.test_result(f"Cmdlet: {cmdlet.split()[0]}", False, str(e))
                
    def test_privileges(self):
        """Test if running with appropriate privileges"""
        if self.system == "Linux":
            is_root = os.geteuid() == 0
            if is_root:
                print("  Running as root - all checks available")
            else:
                self.test_warning("Privileges", 
                                "Not running as root - some checks may fail")
        elif self.system == "Windows":
            try:
                import ctypes
                is_admin = ctypes.windll.shell32.IsUserAnAdmin()
                if is_admin:
                    print("  Running as administrator - all checks available")
                else:
                    self.test_warning("Privileges",
                                    "Not running as administrator - some checks may fail")
            except:
                self.test_warning("Privileges", "Could not determine admin status")
                
    def test_json_export(self):
        """Test JSON export functionality"""
        test_data = {
            "test": "data",
            "nested": {"key": "value"},
            "array": [1, 2, 3]
        }
        
        try:
            json_str = json.dumps(test_data, indent=2)
            parsed = json.loads(json_str)
            self.test_result("JSON Export", parsed == test_data)
            return True
        except Exception as e:
            self.test_result("JSON Export", False, str(e))
            return False
            
    def run_all_tests(self):
        """Run complete test suite"""
        self.print_header("Compliance Audit Tool - Environment Test")
        print(f"System: {self.system}")
        print(f"Python: {sys.version}")
        
        self.print_header("Core Functionality Tests")
        self.test_python_version()
        self.test_file_system_access()
        self.test_command_execution()
        self.test_json_export()
        
        self.print_header("Privilege Tests")
        self.test_privileges()
        
        if self.system == "Linux":
            self.print_header("Linux-Specific Tests")
            self.test_linux_files()
            self.test_linux_commands()
        elif self.system == "Windows":
            self.print_header("Windows-Specific Tests")
            self.test_windows_commands()
            
        self.print_header("Test Summary")
        print(f"Tests Passed: {self.tests_passed}")
        print(f"Tests Failed: {self.tests_failed}")
        print(f"Warnings: {len(self.warnings)}")
        
        if self.warnings:
            print("\nWarnings Details:")
            for warning in self.warnings:
                print(f"  ⚠ {warning}")
                
        print("\nRecommendations:")
        if self.tests_failed > 0:
            print("  ✗ CRITICAL: Some tests failed. Review errors before deployment.")
        elif len(self.warnings) > 0:
            print("  ⚠ Some features may not work. Review warnings.")
            print("  ⚠ Consider running with elevated privileges for full functionality.")
        else:
            print("  ✓ All tests passed! Tool should work correctly.")
            
        if self.system == "Linux" and os.geteuid() != 0:
            print("\n  💡 Tip: Run with 'sudo' for complete audit capabilities")
        elif self.system == "Windows":
            print("\n  💡 Tip: Run PowerShell as Administrator for complete audit capabilities")
            
        return self.tests_failed == 0

if __name__ == "__main__":
    tester = AuditTester()
    success = tester.run_all_tests()
    sys.exit(0 if success else 1)