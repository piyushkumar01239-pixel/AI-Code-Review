# 🛡 CodeGuard — AI-Powered Security Code Review

A web application that finds security vulnerabilities in your code instantly.

## 🚀 What it does

- Detects security vulnerabilities in your code
- Gives each scan a security score (0-100)
- Shows severity levels (Critical, High, Medium, Low)
- Explains each issue and how to fix it
- Saves scan history so you can track progress

## 🔍 Vulnerabilities detected

- Hardcoded passwords and API keys
- SQL Injection
- Cross-Site Scripting (XSS)
- Command Injection (eval, exec)
- Weak cryptography (MD5, SHA1)
- Unsafe deserialization (pickle)
- Flask debug mode exposure

## 🛠 Tech stack

- Python + Flask
- SQLite database
- Flask-Login for authentication
- Werkzeug for password hashing

## ⚙️ Setup

```bash
# Clone the repo
git clone https://github.com/piyushkumar01239-pixel/AI-Code-Review.git
cd AI-Code-Review

# Create virtual environment
python -m venv venv
venv\Scripts\activate

# Install packages
pip install -r requirements.txt

# Set up environment
cp .env.example .env

# Run the app
python app.py
```

Open http://127.0.0.1:5000 in your browser.

## 📌 Project status

This project is being built incrementally — each commit adds a new feature.

## 🗺 Roadmap

- [x] User authentication
- [x] Security scanner
- [x] Scan history
- [x] Dashboard with stats
- [ ] File upload scanning
- [ ] PDF report download
- [ ] AI-powered explanations