# modules/metadata.py
import exifread
from colorama import Fore

def extract_metadata(filepath):
    print(Fore.BLUE + f"\n[+] Extracting metadata from: {filepath}")
    try:
        with open(filepath, 'rb') as f:
            tags = exifread.process_file(f, details=False)
        if not tags:
            print(Fore.YELLOW + "  • No EXIF metadata found.")
            return {}
        print(Fore.GREEN + "  • Found metadata:")
        meta = {}
        for tag, val in tags.items():
            meta[tag] = str(val)
            print(Fore.CYAN + f"     - {tag}: {val}")
        return meta
    except FileNotFoundError:
        print(Fore.RED + "  • File not found. Check path and try again.")
        return {}
    except Exception as e:
        print(Fore.RED + f"[!] Metadata extraction error: {e}")
        return {}
