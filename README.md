# JSentinel 🔍⚡

> Passive JavaScript Analysis Tool for Bug Bounty Hunters

JSentinel is a fast and lightweight Go-based tool designed to analyze JavaScript files and extract security-relevant information during bug bounty reconnaissance.

---

## ✨ Features

- 🔎 Extract endpoints & API paths
- 🌐 Discover domains inside JS
- 🔐 Detect possible secrets:
  - Google API Keys
  - GitHub Tokens
  - Generic API keys
- ⚠️ Identify dangerous sinks:
  - `eval`
  - `fetch`
  - `XMLHttpRequest`
- 🧠 Extract interesting lines (auth, tokens, etc.)
- 📄 Generate Markdown reports
- ⚡ Fast & concurrent scanning
- 🐧 Works on all Linux systems

---

## 🚀 Installation

```bash
git clone https://github.com/Hamt3er/jsentinel.git
cd jsentinel
go build -o jsentinel ./cmd/jsentinel
