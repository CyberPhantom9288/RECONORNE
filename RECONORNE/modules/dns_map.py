# modules/dns_map.py
import dns.resolver
from colorama import Fore

SUBDOMAINS = [
    "www", "mail", "ftp", "dev", "test", "portal", "vpn", "cpanel",
    "api", "blog", "staging", "admin", "beta"
]

def dns_map(domain):
    print(Fore.BLUE + f"\n[+] DNS Map for: {domain}")
    found = []
    for sub in SUBDOMAINS:
        full = f"{sub}.{domain}"
        try:
            answers = dns.resolver.resolve(full, 'A', lifetime=4)
            ips = [a.to_text() for a in answers]
            found.append((full, ips))
            print(Fore.GREEN + f"  • {full} -> {', '.join(ips)}")
        except dns.resolver.NoAnswer:
            pass
        except dns.resolver.NXDOMAIN:
            pass
        except Exception:
            pass

    if not found:
        print(Fore.YELLOW + "  • No subdomains found in quick scan.")
    return found
