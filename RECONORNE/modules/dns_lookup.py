# modules/dns_lookup.py
import dns.resolver
from colorama import Fore

def dns_lookup(domain):
    try:
        print(Fore.BLUE + f"\n[+] DNS records for: {domain}")
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT']
        for q in record_types:
            try:
                answers = dns.resolver.resolve(domain, q, lifetime=6)
                print(Fore.GREEN + f"\n  ├─ {q} records:")
                for r in answers:
                    print(Fore.CYAN + f"     - {r.to_text()}")
            except dns.resolver.NoAnswer:
                print(Fore.YELLOW + f"  ├─ {q}: No record.")
            except dns.resolver.NXDOMAIN:
                print(Fore.RED + f"  ├─ {q}: Domain does not exist.")
                break
            except Exception:
                print(Fore.YELLOW + f"  ├─ {q}: Could not fetch (timeout or blocked).")
    except Exception as e:
        print(Fore.RED + f"[!] DNS lookup error: {e}")
