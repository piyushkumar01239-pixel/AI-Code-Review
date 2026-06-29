# 🛡 CodeGuard — AI-Powered Security Code Review

> Find security vulnerabilities in your code instantly using pattern detection and AI-powered explanations.

![Python](https://img.shields.io/badge/Python-3.10+-blue)
![Flask](https://img.shields.io/badge/Flask-3.0-green)
![AI](https://img.shields.io/badge/AI-Groq%20LLaMA-orange)
![License](https://img.shields.io/badge/License-MIT-purple)

---

## 🚀 What it does

- ✅ Detects security vulnerabilities instantly
- ✅ Gives each scan a security score (0-100)
- ✅ Shows severity levels (Critical, High, Medium, Low)
- ✅ Explains each issue in plain English
- ✅ Suggests concrete fixes for every finding
- ✅ AI-powered summary using Groq LLaMA (free!)
- ✅ Upload files directly (.py, .js, .php, .java)
- ✅ Scan history to track progress over time

---

## 🔍 Vulnerabilities detected

| Vulnerability | Severity |
|---------------|----------|
| Hardcoded passwords & API keys | 🔴 Critical |
| SQL Injection | 🔴 Critical |
| Command Injection | 🔴 Critical |
| Unsafe deserialization (pickle) | 🔴 Critical |
| Dangerous eval() / exec() | 🟠 High |
| Weak cryptography (MD5, SHA1) | 🟠 High |
| Flask debug mode exposure | 🟡 Medium |

---

## 🛠 Tech stack

- **Backend:** Python + Flask
- **Database:** SQLite
- **Auth:** Flask-Login + Werkzeug
- **AI:** Groq LLaMA (free API)
- **Frontend:** HTML + CSS (no framework)

---

## ⚙️ Setup

```bash
# Clone the repo
git clone https://github.com/piyushkumar01239-pixel/AI-Code-Review.git
cd AI-Code-Review

# Create virtual environment
python -m venv venv
venv\Scripts\activate      # Windows
source venv/bin/activate   # Mac/Linux

# Install packages
pip install -r requirements.txt

# Set up environment
cp .env.example .env
# Add your GROQ_API_KEY to .env

# Run the app
python app.py
```

Open **http://127.0.0.1:5000** in your browser.

---

## 🗺 Roadmap

- [x] User authentication
- [x] Security pattern scanner
- [x] AI-powered summaries (Groq)
- [x] File upload scanning
- [x] Scan history
- [x] Dashboard with stats
- [ ] PDF report download
- [ ] More language support
- [ ] GitHub repo scanning
- [ ] VS Code extension

---

## 📄 License

MIT — free to use and modify.