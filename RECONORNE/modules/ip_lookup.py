# modules/ip_lookup.py
import requests
from colorama import Fore

def ip_lookup(ip):
    try:
        print(Fore.BLUE + f"\n[+] IP Lookup for: {ip}")
        resp = requests.get(f"http://ip-api.com/json/{ip}", timeout=8)
        data = resp.json()
        if data.get("status") == "success":
            print(Fore.GREEN + f"  • IP: {ip}")
            print(Fore.CYAN + f"    ├─ Country : {data.get('country')}")
            print(Fore.CYAN + f"    ├─ Region  : {data.get('regionName')}")
            print(Fore.CYAN + f"    ├─ City    : {data.get('city')}")
            print(Fore.CYAN + f"    ├─ ISP     : {data.get('isp')}")
            print(Fore.CYAN + f"    └─ Org     : {data.get('org')}")
        else:
            print(Fore.YELLOW + "  • No data found or invalid IP.")
    except Exception as e:
        print(Fore.RED + f"[!] IP lookup error: {e}")
