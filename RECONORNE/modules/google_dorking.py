# modules/google_dorking.py
import webbrowser
from colorama import Fore

DORKS = {
    "Directory listing": 'intitle:"index of" "{target}"',
    "Sensitive files": 'ext:sql | ext:xml | ext:json "{target}"',
    "Login pages": 'inurl:login "{target}"',
    "Config files": 'ext:env | ext:ini "{target}"',
    "PDF docs": 'filetype:pdf "{target}"',
    "Subdomains": 'site:{target} -www.{target}'
}

def google_dork(target):
    print(Fore.BLUE + f"\n[+] Opening Google Dorking queries for: {target}")
    for name, query in DORKS.items():
        search_query = query.format(target=target)
        url = f"https://www.google.com/search?q={search_query}"
        print(Fore.GREEN + f"  • {name}: {url}")
        try:
            webbrowser.open(url)
        except:
            pass
