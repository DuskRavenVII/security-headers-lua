# 🔒 Security Headers Checker

<div align="center">

![Lua](https://img.shields.io/badge/Lua-5.1+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey.svg)

**A lightweight, fast, and comprehensive security headers analyzer for web applications**

[Features](#-features) • [Installation](#-installation) • [Usage](#-usage) • [Examples](#-examples) • [Contributing](#-contributing)

</div>

---

## 📖 About

Security Headers Checker is a command-line tool written in **Lua** that analyzes HTTP security headers of any website and provides a detailed security report. It helps developers and security researchers identify missing or misconfigured security headers that could expose web applications to various attacks.

### 🎯 Why This Tool?

- ✅ **Lightweight**: No heavy dependencies, just Lua and cURL
- ✅ **Cross-Platform**: Works on Linux, Windows, and macOS
- ✅ **Fast**: Analyzes headers in milliseconds
- ✅ **Detailed Reports**: Provides both text and JSON output
- ✅ **Cookie Analysis**: Checks security flags on cookies
- ✅ **Redirect Chain Detection**: Identifies HSTS issues on redirects

---

## ✨ Features

### 🔍 Security Headers Analysis
- **Strict-Transport-Security (HSTS)**: Validates max-age and includeSubDomains
- **Content-Security-Policy (CSP)**: Checks for unsafe-inline and unsafe-eval
- **X-Frame-Options**: Prevents clickjacking attacks
- **X-Content-Type-Options**: Prevents MIME sniffing
- **Referrer-Policy**: Controls referrer information leakage
- **Permissions-Policy**: Validates browser feature permissions

### 🍪 Cookie Security Analysis
- Checks for `Secure` flag
- Validates `HttpOnly` flag
- Ensures `SameSite` attribute is present

### 🔄 Redirect Chain Detection
- Identifies missing HSTS on initial redirects
- Tracks the full redirect path

### 📊 Grading System
- **A+ (90-100%)**: Excellent security configuration
- **A (80-89%)**: Good security with minor issues
- **B (70-79%)**: Acceptable but needs improvement
- **C (60-69%)**: Below average, significant issues
- **D (50-59%)**: Poor security configuration
- **F (0-49%)**: Critical security vulnerabilities

---

## 🚀 Installation

### Prerequisites
- **Lua 5.1+** (or LuaJIT)
- **cURL** (must be installed and in PATH)

### Quick Install

#### Linux/macOS
```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/security-headers.git
cd security-headers

# Make it executable (optional)
chmod +x main.lua

# Run directly
lua main.lua https://example.com
