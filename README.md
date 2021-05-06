# ISWA-Python

A Python port of the Invest Secure Web Application (ISWA). ISWA is an intentionally vulnerable web application used for demontration and teaching purposes.

## Recommended Tools

- A password cracking tool
    - https://hashcat.net/hashcat/
    - https://www.openwall.com/john/
- Wordlists
    - https://github.com/danielmiessler/SecLists
- A HTTP Proxy / Testing tool
    - https://owasp.org/www-project-zap/
    - https://portswigger.net/burp/communitydownload

## Dependencies

- Works on Linux and MacOS
- Never tested on Windows
- Requires Docker and Docker Compose
    - Refer to the docker website for installation on your OS

## Installation

```
git clone https://github.com/Shreda/ISWA-Python.git
cd ISWA-Python
docker-compose up
```

## Usage

- Once the project comes up you can view the web application on http://localhost:5000
- For code review, all the applications API endpoints are defined in `iswa/app.py`

## Vulnerabilities

### Authentication - Username Enumeration

### Authentication - Weak Password Policy

### Authentication - Lack of Brute Force Protections

### Authentication - Lack of MFA

### Authentication - Allowing Known Weak Passwords

### Authentication - Use of Weak Password Hashing Algorithms

### Injection - Command Injection

### Injection - SQL Injection

