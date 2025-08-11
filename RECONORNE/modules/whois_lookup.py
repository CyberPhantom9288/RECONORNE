# modules/whois_lookup.py
import whois
from colorama import Fore

def whois_lookup(domain):
    try:
        print(Fore.BLUE + f"\n[+] WHOIS lookup for: {domain}")
        info = whois.whois(domain)
        # info fields can be lists; handle gracefully
        registrar = info.registrar
        creation = info.creation_date
        expiration = info.expiration_date
        nameservers = info.name_servers
        emails = info.emails

        print(Fore.GREEN + f"  • Domain: {domain}")
        print(Fore.CYAN + f"    ├─ Registrar: {registrar}")
        print(Fore.CYAN + f"    ├─ Creation: {creation}")
        print(Fore.CYAN + f"    ├─ Expiration: {expiration}")
        print(Fore.CYAN + f"    ├─ Name servers: {nameservers}")
        print(Fore.CYAN + f"    └─ Contact emails: {emails}")
    except Exception as e:
        print(Fore.RED + f"[!] WHOIS lookup failed: {e}")
