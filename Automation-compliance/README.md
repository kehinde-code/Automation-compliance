\# Compliance Audit Tools



Automated compliance auditing tools for Python and PowerShell that reduce audit time by 80-95%.



\## 🎯 Features



\- \*\*Automated Compliance Checks\*\*: Password policies, firewall status, services, patches, and more

\- \*\*Multi-Format Reports\*\*: JSON, CSV, and HTML reports with executive summaries

\- \*\*Risk-Based Prioritization\*\*: Findings categorized by severity (CRITICAL, HIGH, MEDIUM, LOW)

\- \*\*Cross-Platform\*\*: Python tool supports Linux/Unix, PowerShell tool for Windows

\- \*\*Actionable Remediation\*\*: Each finding includes specific remediation commands

\- \*\*Audit Trail\*\*: Timestamped findings for compliance documentation



\## 📋 Requirements



\### Python Tool

\- \*\*Python\*\*: 3.6 or higher

\- \*\*OS\*\*: Linux, Unix, macOS

\- \*\*Privileges\*\*: Root/sudo recommended for complete checks

\- \*\*Dependencies\*\*: Standard library only (no external packages required)



\### PowerShell Tool

\- \*\*PowerShell\*\*: 5.1 or higher

\- \*\*OS\*\*: Windows Server 2012+ / Windows 10+

\- \*\*Privileges\*\*: Administrator rights recommended for complete checks



\## 🚀 Quick Start



\### Testing Before Use



\*\*Always run the test suite first to verify compatibility:\*\*



```bash

\# Python

python3 test\_audit\_environment.py



\# PowerShell (Run as Administrator)

.\\test\_audit\_environment.ps1

```



\### Running the Python Audit



```bash

\# Basic usage

sudo python3 compliance\_audit.py



\# Custom output directory

sudo python3 compliance\_audit.py --output /path/to/reports

```



\### Running the PowerShell Audit



```powershell

\# Run as Administrator

Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

.\\ComplianceAudit.ps1 -OutputDirectory "C:\\AuditReports"

```



\## 📂 Repository Structure



```

Automation-compliance/

├── .github/

│   └── workflows/

│       └── test.yml              # GitHub Actions CI/CD

├── compliance\_audit.py           # Main Python audit tool

├── test\_audit\_environment.py     # Python test suite

├── ComplianceAudit.ps1          # Main PowerShell audit tool (optional)

├── .gitignore                    # Git ignore file

├── README.md                     # This file

└── LICENSE                       # License file

```



\## 🔧 Configuration



\### Customizing Checks



Edit the `main()` function in each script to customize:



\*\*Python:\*\*

```python

\# Add custom file checks

critical\_files = \[

&nbsp;   '/etc/passwd',

&nbsp;   '/etc/shadow',

&nbsp;   '/etc/ssh/sshd\_config',

&nbsp;   '/var/www/html/.htaccess'  # Add your files

]

auditor.check\_file\_permissions(critical\_files)



\# Add prohibited services

prohibited = \['telnet', 'rsh', 'ftp', 'your-service']

auditor.check\_running\_services(prohibited)

```



\*\*PowerShell:\*\*

```powershell

\# Add prohibited services

$prohibitedServices = @(

&nbsp;   "TelnetServer",

&nbsp;   "RemoteRegistry",

&nbsp;   "SNMP",

&nbsp;   "YourService"

)

$auditor.CheckServices($prohibitedServices)

```



\## 📊 Output Examples



\### JSON Output

```json

{

&nbsp; "summary": {

&nbsp;   "total\_checks": 45,

&nbsp;   "by\_status": {

&nbsp;     "PASS": 38,

&nbsp;     "FAIL": 5,

&nbsp;     "WARNING": 2

&nbsp;   },

&nbsp;   "failures\_by\_severity": {

&nbsp;     "CRITICAL": 2,

&nbsp;     "HIGH": 3

&nbsp;   }

&nbsp; },

&nbsp; "findings": \[...]

}

```



\### HTML Report

Interactive HTML report with:

\- Executive summary with statistics

\- Color-coded findings by severity

\- Sortable/filterable table

\- Remediation commands



\## 🧪 Testing Strategy



\### 1. Run Environment Tests

```bash

\# This validates your environment

python3 test\_audit\_environment.py

```



\### 2. Run Audit in Test Mode

```bash

\# Create test output directory

mkdir -p /tmp/audit\_test



\# Run audit pointing to test directory

sudo python3 compliance\_audit.py



\# Verify outputs were created

ls -lh audit\_reports/

```



\### 3. Validate Reports

```bash

\# Check JSON is valid

cat audit\_reports/audit\_results\_\*.json | python3 -m json.tool



\# Open HTML report in browser

xdg-open audit\_reports/audit\_report\_\*.html

```



\## ⚙️ Known Limitations



\### Python Tool

\- \*\*UFW Firewall\*\*: Requires UFW installed (use `iptables` checks if using different firewall)

\- \*\*systemd\*\*: Requires systemd (adjust for SysV init or other init systems)

\- \*\*SELinux/AppArmor\*\*: Not currently checked (can be added)

\- \*\*Package Manager\*\*: Does not check installed software versions (can use `dpkg`, `rpm`, etc.)



\### PowerShell Tool

\- \*\*BitLocker\*\*: Requires BitLocker feature enabled

\- \*\*Windows Update\*\*: COM object may have limitations on some systems

\- \*\*Domain Policies\*\*: Only checks local policies (extend for GPO checks)



\## 🔒 Security Considerations



1\. \*\*Credentials\*\*: Never store credentials in the scripts

2\. \*\*Permissions\*\*: Scripts require elevated privileges - review before granting

3\. \*\*Output Files\*\*: Contain sensitive system information - protect accordingly

4\. \*\*Network\*\*: Some checks may trigger IDS/IPS alerts - coordinate with security team



\## 🤝 Contributing



Contributions welcome! Please:



1\. Fork the repository

2\. Create a feature branch (`git checkout -b feature/new-check`)

3\. Test thoroughly (run test suite)

4\. Commit changes (`git commit -am 'Add new compliance check'`)

5\. Push to branch (`git push origin feature/new-check`)

6\. Create Pull Request



\### Adding New Checks



To add custom checks:



```python

def check\_custom\_requirement(self):

&nbsp;   """Check your custom requirement"""

&nbsp;   category = "Custom Category"

&nbsp;   

&nbsp;   try:

&nbsp;       # Your check logic here

&nbsp;       result = subprocess.run(\['your-command'], capture\_output=True, text=True)

&nbsp;       

&nbsp;       if result.returncode == 0:

&nbsp;           self.add\_finding(category, "Your Check Name", "PASS", "MEDIUM",

&nbsp;                          "Check passed successfully")

&nbsp;       else:

&nbsp;           self.add\_finding(category, "Your Check Name", "FAIL", "HIGH",

&nbsp;                          "Check failed", "Remediation command here")

&nbsp;   except Exception as e:

&nbsp;       self.add\_finding(category, "Your Check Name", "WARNING", "LOW",

&nbsp;                      f"Could not run check: {str(e)}")

```



\## 📝 Changelog



\### Version 1.0.0 (Initial Release)

\- Password policy checks

\- File permission auditing

\- Service monitoring

\- Firewall verification

\- Multi-format reporting (JSON, CSV, HTML)

\- Cross-platform support



\## 📄 License



MIT License - see \[LICENSE](LICENSE) file for details.



\## 🆘 Support



\- \*\*Issues\*\*: Report bugs via \[GitHub Issues](https://github.com/yourusername/Automation-compliance/issues)

\- \*\*Documentation\*\*: See this README

\- \*\*Examples\*\*: Check the `audit\_reports/` directory after running



\## 🎓 Best Practices



1\. \*\*Schedule Regular Audits\*\*: Run weekly or monthly using cron/Task Scheduler

2\. \*\*Version Control Results\*\*: Track compliance over time in separate repository

3\. \*\*Automate Remediation\*\*: Use output to drive automation workflows

4\. \*\*Integrate with SIEM\*\*: Export findings to security tools

5\. \*\*Review and Update\*\*: Regularly update checks for new requirements



\## ⏱️ Performance



\- \*\*Python\*\*: ~5-15 seconds for typical audit (30-50 checks)

\- \*\*PowerShell\*\*: ~10-30 seconds for typical audit (40-60 checks)

\- Time varies based on system responsiveness and check complexity



\## 🎯 Roadmap



\- \[ ] Add compliance framework templates (CIS, NIST, PCI-DSS)

\- \[ ] Database storage backend option

\- \[ ] REST API for integration

\- \[ ] Real-time monitoring mode

\- \[ ] Automated remediation workflows

\- \[ ] Docker container support

\- \[ ] Cloud platform support (AWS, Azure, GCP)



\## ✅ Tested On



\- Ubuntu 22.04 LTS - Full functionality

\- Ubuntu 20.04 LTS - Full functionality  

\- Debian 11 - Partial (no UFW by default)

\- RHEL 8 - Partial (uses firewalld instead of UFW)



\## 📞 Contact



For questions or suggestions, please open an issue on GitHub.



---



\*\*Note\*\*: These tools are provided as-is. Always test in non-production environments first and review all checks before deploying to production systems.

