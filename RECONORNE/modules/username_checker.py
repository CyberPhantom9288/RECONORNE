# modules/username_checker.py
import requests
from colorama import Fore

PLATFORMS = {
    "GitHub": "https://github.com/{}",
    "Twitter": "https://twitter.com/{}",
    "Instagram": "https://www.instagram.com/{}",
    "Reddit": "https://www.reddit.com/user/{}",
    "Facebook": "https://www.facebook.com/{}",
    "Medium": "https://medium.com/@{}",
    "Pinterest": "https://www.pinterest.com/{}",
    "Tumblr": "https://{}.tumblr.com"
}

HEADERS = {"User-Agent": "Mozilla/5.0 (SnoopyRecon)"}

def check_username(username, timeout=6):
    print(Fore.BLUE + f"\n[+] Checking username: {username}")
    found_any = False
    for name, url_tpl in PLATFORMS.items():
        profile = url_tpl.format(username)
        try:
            r = requests.get(profile, headers=HEADERS, timeout=timeout, allow_redirects=True)
            status = r.status_code
            if status == 200:
                print(Fore.GREEN + f"  • {name}: FOUND -> {profile}")
                found_any = True
            elif status in (301, 302):
                print(Fore.YELLOW + f"  • {name}: Redirect ({status}) -> {profile}")
            elif status == 404:
                print(Fore.RED + f"  • {name}: Not found")
            else:
                print(Fore.YELLOW + f"  • {name}: HTTP {status}")
        except Exception as e:
            print(Fore.RED + f"  • {name}: Error ({e})")
    if not found_any:
        print(Fore.YELLOW + "  • No accounts found with that username (quick scan).")
    return
