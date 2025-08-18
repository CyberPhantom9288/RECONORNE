# 🕵️ Reconorne - Recon & OSINT Toolkit v2.0  

🚀 A powerful automated reconnaissance and OSINT tool for **Bug Bounty Hunters** & **Penetration Testers**.  
Reconorne helps you collect subdomains, live assets, wayback data, and extract sensitive information — all in one go.  

---

## ✨ Features  
- 🔎 **Subdomain Enumeration**  
  - Collects subdomains from `crt.sh`, `CertSpotter`, and DNS brute-force.  

- 🌐 **Alive Checking**  
  - Multi-threaded detection of live subdomains and URLs.  

- 📜 **Wayback Machine Integration**  
  - Fetches historical URLs from the Internet Archive.  

- 🎯 **URL Filtering**  
  - Extract URLs with parameters (`?`)  
  - Filter by file extensions (`js, pdf, zip, env, log...`)  
  - Include / Exclude URLs based on keywords.  

- 🧩 **Information Extraction**  
  - Emails  
  - Technologies (Apache, Nginx, Node.js, WordPress, etc.)  
  - IP addresses  
  - Databases (MySQL, PostgreSQL, MongoDB, etc.)  
  - Secrets & leaks (API keys, tokens, passwords)  
  - Interesting files (`.js`, `.sql`, `.zip`, `.env`, `.log`)  
---

## ⚙️ Installation  

```bash
# Clone the repo
git clone https://github.com/CyberPhantom9288/Reconorne.git
cd Reconorne

# Install dependencies
pip install -r requirements.txt
