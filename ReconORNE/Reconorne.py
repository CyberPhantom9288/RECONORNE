#!/usr/bin/env python3

import requests
import tldextract
import dns.resolver
import argparse
import re
from pyfiglet import figlet_format
from termcolor import colored
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
# Stylish banner
def banner():
    print("""
\033[1;36m
██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗ ██████╗ ██████╗ ███╗   ██╗███████╗
██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║██╔═══██╗██╔══██╗████╗  ██║██╔════╝
██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║██║   ██║██████╔╝██╔██╗ ██║█████╗  
██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║██║   ██║██╔══██╗██║╚██╗██║██╔══╝  
██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║╚██████╔╝██║  ██║██║ ╚████║███████╗
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝
                        
                    Recon & OSINT Toolkit v2.0 🚀
                                                        -by CyberPhantom9288
\033[0m
    """)


def extract_root(domain):
    tld = tldextract.extract(domain)
    return f"{tld.domain}.{tld.suffix}"

def make_output_dir():
    Path("output").mkdir(exist_ok=True)

def save_file(name, content):
    make_output_dir()
    with open(f"output/{name}", "w") as f:
        for line in sorted(set(content)):
            f.write(line + "\n")

def print_section(title, data):
    print(colored(f"\n==[ {title} ]==", "cyan"))
    if data:
        for item in sorted(set(data)):
            print(item)
    else:
        print("No data found.")

def get_crtsh(domain):
    try:
        r = requests.get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=10)
        subdomains = set()
        if r.ok:
            for cert in r.json():
                for name in cert['name_value'].split('\n'):
                    if domain in name:
                        subdomains.add(name.strip())
        return sorted(subdomains)
    except:
        return []

def get_certspotter(domain):
    try:
        r = requests.get(f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names", timeout=10)
        subs = set()
        if r.ok:
            for cert in r.json():
                for name in cert.get('dns_names', []):
                    if domain in name:
                        subs.add(name.strip())
        return sorted(subs)
    except:
        return []

def dns_bruteforce(domain):
    wordlist = ["www", "mail", "dev", "api", "admin", "ftp", "blog", "cdn", "m"]
    found = []
    resolver = dns.resolver.Resolver()
    for sub in wordlist:
        fqdn = f"{sub}.{domain}"
        try:
            resolver.resolve(fqdn, 'A')
            found.append(fqdn)
        except:
            continue
    return found

def check_alive(url):
    try:
        res = requests.head(url, timeout=5, allow_redirects=True)
        if res.status_code < 400:
            return url
    except:
        pass
    return None

def get_wayback_urls(domain):
    try:
        r = requests.get(f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=text&fl=original&collapse=urlkey", timeout=10)
        return list(set(r.text.strip().split('\n'))) if r.ok else []
    except:
        return []

def extract_info_from_urls(urls):
    emails, techs, ips, databases, leaks, ext_files = [], [], [], [], [], []
    ip_pattern = r"(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)"
    for url in urls:
        try:
            r = requests.get(url, timeout=7)
            content = r.text
            if r.status_code < 400:
                emails += re.findall(r"[\w.-]+@[\w.-]+\.[a-zA-Z]{2,}", content)
                techs += re.findall(r"(Apache|Nginx|PHP|Node\.js|Express|Tomcat|Jenkins|WordPress|Drupal|Laravel|Spring)", content, re.I)
                ips += re.findall(ip_pattern, content)
                databases += re.findall(r"(MySQL|PostgreSQL|MongoDB|Redis|MariaDB|Oracle)", content, re.I)
                leaks += re.findall(r"(api_key|secret|token|password|admin)", content, re.I)
        except:
            continue
        if any(url.lower().endswith(ext) for ext in [".js", ".json", ".xml", ".pdf", ".sql", ".zip", ".env", ".log"]):
            ext_files.append(url)
    return {
        "emails": sorted(set(emails)),
        "technologies": sorted(set(techs)),
        "ips": sorted(set(ips)),
        "databases": sorted(set(databases)),
        "leaks": sorted(set(leaks)),
        "ext_files": sorted(set(ext_files))
    }

def main():
    banner()
    parser = argparse.ArgumentParser(description="ReconX by CyberPhantom9288 - Deep Recon Tool")
    parser.add_argument("-d", "--domain", required=True, help="Target domain")
    parser.add_argument("--params", action="store_true", help="Show only URLs with parameters")
    parser.add_argument("--ext", help="Filter by extensions (e.g. js,pdf,zip)")
    parser.add_argument("--include", help="Include subdomain keywords (comma-separated)")
    parser.add_argument("--exclude", help="Exclude subdomain keywords (comma-separated)")
    args = parser.parse_args()

    domain = extract_root(args.domain)

    subdomains = set(get_crtsh(domain) + get_certspotter(domain) + dns_bruteforce(domain))
    print_section("All Subdomains", subdomains)
    save_file("subdomains.txt", subdomains)

    with ThreadPoolExecutor(max_workers=20) as executor:
        live_subs = list(filter(None, executor.map(lambda s: check_alive(f"http://{s}"), subdomains)))
    print_section("Live Subdomains", live_subs)
    save_file("subdomains_live.txt", live_subs)

    all_urls = []
    for sub in subdomains:
        all_urls += get_wayback_urls(sub)
    all_urls = sorted(set([u for u in all_urls if u.startswith("http")]))
    print_section("All URLs", all_urls)
    save_file("urls.txt", all_urls)

    with ThreadPoolExecutor(max_workers=30) as executor:
        live_urls = list(filter(None, executor.map(check_alive, all_urls)))
    print_section("Live URLs", live_urls)
    save_file("urls_live.txt", live_urls)

    if args.params:
        param_urls = [u for u in live_urls if "?" in u]
        print_section("URLs with Parameters", param_urls)
        save_file("urls_with_params.txt", param_urls)

    if args.ext:
        ext_list = [e.strip() for e in args.ext.split(",")]
        ext_urls = [u for u in live_urls if any(u.lower().endswith(f".{ext}") for ext in ext_list)]
        print_section(f"URLs with Extensions: {args.ext}", ext_urls)
        save_file("urls_with_ext.txt", ext_urls)

    if args.include:
        keywords = args.include.split(",")
        inc_urls = [u for u in live_urls if any(k in u for k in keywords)]
        print_section("Included Subdomain URLs", inc_urls)
        save_file("urls_included.txt", inc_urls)

    if args.exclude:
        keywords = args.exclude.split(",")
        exc_urls = [u for u in live_urls if all(k not in u for k in keywords)]
        print_section("Excluded Subdomain URLs", exc_urls)
        save_file("urls_excluded.txt", exc_urls)

    print(colored("\n[+] Extracting sensitive information from live URLs...\n", "yellow"))
    info = extract_info_from_urls(live_urls)

    for key, value in info.items():
        print_section(f"{key.title().replace('_',' ')}", value)
        save_file(f"{key}.txt", value)

if __name__ == "__main__":
    main()
