# 🛡️ PEGASUS - Unified Web Vulnerability Toolkit

PEGASUS (Penetration & Exploitation Generator for Advanced Scanning of Unsecured Sites) is a powerful CLI-based web application penetration testing suite written in Python 3. It provides a comprehensive set of tools for identifying and exploiting common web vulnerabilities without relying on AI, using real-world pentesting techniques.

## 🔖 Project Description

- **Name**: PEGASUS – Penetration & Exploitation Generator for Advanced Scanning of Unsecured Sites
- **Type**: CLI-based Web Application Pentest Suite
- **Language**: Python 3
- **Author**: letda kes dr. Sobri, S.Kom
- **GitHub**: [github.com/sobri3195](https://github.com/sobri3195)
- **Contact**: muhammadsobrimaulana31@gmail.com
- **Support**: [lynk.id/muhsobrimaulana](https://lynk.id/muhsobrimaulana)

## ✅ Core Features

- **🔍 SQL Injection Scanner**
  - Inject payload (' OR 1=1, UNION, sleep())
  - Multi-vector: GET, POST, cookies, headers
  - Support time-based & error-based detection

- **💉 XSS Scanner**
  - Test parameters, forms, and cookies
  - Automatic payload reflection testing
  - Stored XSS simulation (if DB available)

- **🧪 CSRF Exploit Builder**
  - Detect forms without tokens
  - Extract tokens from other pages
  - Automatic PoC HTML attack page generation

- **📂 Directory & File Brute Forcer**
  - Scan paths like /admin, /.env, /db.sql
  - Check HTTP response, content length, size

- **🧠 Session Analyzer**
  - Session fixation & hijacking detection
  - Cookie security analysis
  - Missing security headers check

- **📑 JavaScript Analyzer**
  - Extract and analyze JavaScript files
  - Find sensitive data and API endpoints
  - Sourcemap & JS secrets extraction

- **🚪 403 Bypass Tester**
  - Test various bypass techniques
  - Header injection methods
  - Alternative HTTP methods

## 💡 Advanced Features

- **🌐 Subdomain Bruteforcer + Takeover Checker**
- **🔗 Open Redirect + Cache Poison Simulation**
- **🧰 Tech Stack Fingerprinter**
- **🔎 Parameter Pollution Testing**
- **🛡️ Custom Payload Builder**

## 🧰 Tech Stack

| Library/Tool | Purpose |
|-------------|----------|
| requests, httpx | HTTP Scanner and Payload Delivery |
| BeautifulSoup | Parsing form, HTML, response |
| argparse, click | CLI modular input |
| termcolor | Styling scanner results |
| multiprocessing | Parallel scanning |

## 📁 Project Structure

```
pegasus/
├── core/
│   ├── sqli_scanner.py
│   ├── xss_scanner.py
│   ├── csrf_tester.py
│   ├── dir_brute.py
│   ├── session_analyzer.py
│   ├── js_analyzer.py
│   └── bypasser.py
├── utils/
│   ├── http.py
│   ├── parser.py
│   ├── payloads.py
│   └── colors.py
├── wordlists/
│   ├── dir.txt
│   ├── userpass.txt
│   └── params.txt
├── pegasus.py
├── requirements.txt
└── README.md
```

## 🚀 Installation

1. Clone the repository:
```bash
git clone https://github.com/sobri3195/pegasus.git
cd pegasus
```

2. Install the required dependencies:
```bash
pip install -r requirements.txt
```

## 🎯 Usage

PEGASUS requires an activation code for first-time use. The activation code is "sobri".

Basic usage:
```bash
python pegasus.py --target https://example.com [options]
```

### Command Line Options

- `--target`: Target URL to scan (required)
- `--sqli`: Enable SQL Injection scanning
- `--xss`: Enable XSS scanning
- `--csrf`: Enable CSRF scanning
- `--dir`: Enable directory bruteforcing
- `--session`: Enable session analysis
- `--js`: Enable JavaScript analysis
- `--bypass`: Enable 403 bypass testing

### Examples

Scan for SQL injection vulnerabilities:
```bash
python pegasus.py --target https://example.com --sqli
```

Comprehensive scan with all modules:
```bash
python pegasus.py --target https://example.com --sqli --xss --csrf --dir --session --js --bypass
```

## 🔐 Security Features

PEGASUS includes built-in security measures to prevent unauthorized modifications:
- Identity validation system (checks tool name, author, and email)
- Activation code requirement ("sobri")
- Protection against unauthorized code changes

## ✉️ Contact

**Author**: letda kes dr. Sobri, S.Kom
- 📧 Email: muhammadsobrimaulana31@gmail.com
- 🔗 GitHub: [github.com/sobri3195](https://github.com/sobri3195)
- ☕ Support: [lynk.id/muhsobrimaulana](https://lynk.id/muhsobrimaulana)

## ⚠️ Disclaimer

This tool is for educational and authorized penetration testing purposes only. Always obtain proper authorization before testing any system or application. The authors are not responsible for any misuse or damage caused by this program.

## 📋 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- Thanks to all contributors who have helped improve PEGASUS
- Special thanks to the open-source security community 