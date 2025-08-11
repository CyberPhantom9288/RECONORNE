# snoopy_recon.py
from modules import ip_lookup, whois_lookup, dns_lookup, username_checker, metadata, dns_map, email_finder, google_dorking
from colorama import Fore, Style, init
import time

init(autoreset=True)

def banner():
    print(Fore.RED + r"""
  _______  _______  _______  _______  _        _______  _______  _        _______ 
(  ____ )(  ____ \(  ____ \(  ___  )( (    /|(  ___  )(  ____ )( (    /|(  ____ \
| (    )|| (    \/| (    \/| (   ) ||  \  ( || (   ) || (    )||  \  ( || (    \/
| (____)|| (__    | |      | |   | ||   \ | || |   | || (____)||   \ | || (__    
|     __)|  __)   | |      | |   | || (\ \) || |   | ||     __)| (\ \) ||  __)   
| (\ (   | (      | |      | |   | || | \   || |   | || (\ (   | | \   || (      
| ) \ \__| (____/\| (____/\| (___) || )  \  || (___) || ) \ \__| )  \  || (____/\
|/   \__/(_______/(_______/(_______)|/    )_)(_______)|/   \__/|/    )_)(_______/
""")
    print(Fore.YELLOW + "         🔍 OSINT by CyberPhantom9288 🔍")
    print(Style.DIM + "-" * 50)

def main():
    banner()
    while True:
        print(Fore.CYAN + "\nChoose an OSINT option:")
        print(" 1. IP Lookup")
        print(" 2. WHOIS Domain Lookup")
        print(" 3. DNS Record Fetcher")
        print(" 4. Username Checker (Social Media)")
        print(" 5. Metadata (EXIF) Extractor")
        print(" 6. DNS Map (subdomain scan)")
        print(" 7. Email Finder (from webpage)")
        print(" 8. Google Dorking (OSINT queries)")
        print(" 0. Exit")

        choice = input(Fore.GREEN + "\n>> ").strip()

        if choice == "1":
            ip = input(Fore.YELLOW + "Enter IP (e.g., 8.8.8.8): ").strip()
            ip_lookup.ip_lookup(ip)

        elif choice == "2":
            domain = input(Fore.YELLOW + "Enter domain (e.g., example.com): ").strip()
            whois_lookup.whois_lookup(domain)

        elif choice == "3":
            domain = input(Fore.YELLOW + "Enter domain (e.g., example.com): ").strip()
            dns_lookup.dns_lookup(domain)

        elif choice == "4":
            username = input(Fore.YELLOW + "Enter username to check: ").strip()
            username_checker.check_username(username)

        elif choice == "5":
            path = input(Fore.YELLOW + "Enter file path (e.g., images/pic.jpg): ").strip()
            metadata.extract_metadata(path)

        elif choice == "6":
            domain = input(Fore.YELLOW + "Enter domain (e.g., example.com): ").strip()
            dns_map.dns_map(domain)

        elif choice == "7":
            url = input(Fore.YELLOW + "Enter webpage URL (e.g., https://example.com): ").strip()
            email_finder.email_finder(url)

        elif choice == "8":
            target = input(Fore.YELLOW + "Enter target keyword or domain: ").strip()
            google_dorking.google_dork(target)
  

        elif choice == "0":
            print(Fore.MAGENTA + "\nExiting OSINT. Stay ethical 🧠")
            time.sleep(0.8)
            break

        else:
            print(Fore.RED + "Invalid option. Try again.")

if __name__ == "__main__":
    main()
