# 🔒 Security Headers Checker

<div align="center">

![Lua](https://img.shields.io/badge/Lua-5.1+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey.svg)
![Version](https://img.shields.io/badge/version-1.0.0-orange.svg)
![Build](https://img.shields.io/badge/build-passing-brightgreen.svg)

**A lightweight, fast, and cross-platform CLI tool written in Lua for analyzing HTTP security headers, cookies, and redirect chains. Outputs detailed reports in both text and JSON formats.**

[Features](#-features) • [Installation](#-installation) • [Usage](#-usage) • [Examples](#-examples) • [Changelog](#-changelog) • [Contributing](#-contributing)

</div>

---

## 📖 About

**Security Headers Checker** is a command-line tool written in **Lua** that analyzes HTTP security headers of any website and provides a detailed security report. It helps developers, system administrators, and security researchers identify missing or misconfigured security headers that could expose web applications to various attacks like XSS, Clickjacking, and MIME sniffing.

### 🎯 Why This Tool?

- ✅ **Lightweight**: No heavy dependencies, just Lua and cURL
- ✅ **Cross-Platform**: Works seamlessly on Linux, Windows, and macOS
- ✅ **Fast**: Analyzes headers in milliseconds
- ✅ **Detailed Reports**: Provides both human-readable text and machine-parseable JSON output
- ✅ **Cookie Analysis**: Checks security flags on cookies (Secure, HttpOnly, SameSite)
- ✅ **Redirect Chain Detection**: Identifies HSTS issues on initial redirects
- ✅ **Bug Bounty Friendly**: JSON output makes it easy to integrate with other tools

---

## ✨ Features

### 🔍 Security Headers Analysis
- **Strict-Transport-Security (HSTS)**: Validates max-age and includeSubDomains
- **Content-Security-Policy (CSP)**: Checks for unsafe-inline and unsafe-eval
- **X-Frame-Options**: Prevents clickjacking attacks
- **X-Content-Type-Options**: Prevents MIME sniffing
- **Referrer-Policy**: Controls referrer information leakage
- **Permissions-Policy**: Validates browser feature permissions syntax

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
git clone https://github.com/DuskRavenVII/security-headers-lua.git
cd security-headers-lua

# Make it executable (optional)
chmod +x main.lua

# Run directly
lua main.lua https://example.com
