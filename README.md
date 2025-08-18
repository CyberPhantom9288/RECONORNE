# 🕵️ Reconorne - Recon & OSINT Toolkit v2.0  

🚀 A powerful automated reconnaissance and OSINT tool for **Bug Bounty Hunters** & **Penetration Testers**.  
Reconorne helps you collect subdomains, live assets, wayback data, and extract sensitive information — all in one go.  

---

🚀 Features

Subdomain enumeration via crt.sh, CertSpotter API, and DNS brute-force

Multi-threaded alive checking for subdomains and URLs

Fetches archived URLs from the Wayback Machine

Supports smart URL filtering:

Parameter URLs (?)

File extensions (.js, .pdf, .sql, .zip, .env, .log)

Include/Exclude keywords for precise targeting

Extracts useful information from live URLs:

Emails

Technologies (Apache, Nginx, Node.js, WordPress, Drupal, etc.)

IP addresses

Databases (MySQL, PostgreSQL, MongoDB, Oracle, etc.)

Secrets & leaks (api_key, token, password, secret, etc.)

Interesting files (.js, .sql, .zip, .env, .log)

Organized output stored in /output directory with separate files

Graceful error handling & clean CLI output

Works on Kali Linux and other Linux distros with Python 3
---

## ⚙️ Installation  

```bash
# Clone the repo
git clone https://github.com/CyberPhantom9288/Reconorne.git
cd Reconorne

# Install dependencies
pip install -r requirements.txt
