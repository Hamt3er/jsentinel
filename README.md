# JSentinel 🔍⚡

> Passive JavaScript Analysis Tool for Bug Bounty Hunters

JSentinel is a fast, lightweight, and practical Go-based tool designed to analyze JavaScript files and extract security-relevant data during bug bounty reconnaissance.

---

## ✨ Features

- 🔎 Extract endpoints & API paths
- 🌐 Discover domains inside JavaScript files
- 🔐 Detect potential secrets:
  - Google API Keys
  - GitHub Tokens
  - Generic API keys & secrets
- ⚠️ Identify dangerous sinks:
  - eval
  - fetch
  - XMLHttpRequest
  - document.write
- 🧠 Extract interesting lines (auth, tokens, configs)
- 📄 Generate Markdown reports
- ⚡ Concurrent & fast scanning
- 🐧 Works on all Linux systems

---

## 🚀 Installation

### 1) Clone the repository

```bash
git clone https://github.com/Hamt3er/jsentinel.git
cd jsentinel
```
---

### 2) Build the tool

```bash
go build -o jsentinel ./cmd/jsentinel
```

---

### 3) Install globally (recommended)

```bash
sudo install -m 755 jsentinel /usr/local/bin/jsentinel
```

✅ Now you can use it from anywhere:

```bash
jsentinel -h
```

---

## 🧪 Usage

### 🔹 Scan a full website

```bash
jsentinel -site https://target.com
```

---

### 🔹 Scan a JavaScript file

```bash
jsentinel -file app.js
```

---

### 🔹 Scan a JS URL

```bash
jsentinel -url https://target.com/app.js
```

---

### 🔹 Save Markdown report

```bash
jsentinel -site https://target.com -md-out report.md
```

---

### 🔹 Save JSON report

```bash
jsentinel -site https://target.com -json-out report.json
```

---

## ⚙️ Options

```text
-file        Path to local JavaScript file
-url         Direct JavaScript URL
-site        Website URL to crawl
-md-out      Output Markdown report
-json-out    Output JSON report
-same-host   Restrict crawling to same host
-max-pages   Maximum number of pages to crawl
-max-js      Maximum number of JS files to analyze
-concurrency Maximum concurrent requests
-timeout     HTTP timeout
```

---

## 📄 Example Output

```text
========== JSentinel Report ==========
Target: https://target.com
Mode: site

API Paths: 12
Suspected Secrets: 3
Dangerous Sinks: 5

[+] Found API:
- /api/user
- /v1/login

[!] Possible Secret:
- Google API Key

[!] Dangerous Sink:
- eval(...)
```

---

## 🧠 Use Cases

* Bug bounty reconnaissance
* JavaScript analysis
* Secret discovery
* API endpoint mapping
* Attack surface expansion

---

## ⚠️ Disclaimer

This tool is intended for authorized security testing and educational purposes only.
Do not use it on systems without proper permission.

---

## 👨‍💻 Author

**Hamt3er**

