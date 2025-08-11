# modules/email_finder.py
import re
import requests
from colorama import Fore

EMAIL_REGEX = r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"

HEADERS = {"User-Agent": "Mozilla/5.0 (SnoopyRecon)"}

def email_finder(url):
    print(Fore.BLUE + f"\n[+] Searching for emails on: {url}")
    try:
        resp = requests.get(url, headers=HEADERS, timeout=8)
        matches = set(re.findall(EMAIL_REGEX, resp.text))
        if matches:
            print(Fore.GREEN + f"  • Found {len(matches)} email(s):")
            for email in matches:
                print(Fore.CYAN + f"     - {email}")
            return matches
        else:
            print(Fore.YELLOW + "  • No emails found.")
            return set()
    except Exception as e:
        print(Fore.RED + f"[!] Error fetching {url}: {e}")
        return set()
