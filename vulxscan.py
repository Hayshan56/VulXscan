import socket
import ssl
import requests
import hashlib
import json
import sys
import time
import random

# Helper colors for terminal
try:
    from colorama import init, Fore, Style
    init(autoreset=True)
except ImportError:
    # fallback plain text
    class Fore:
        RED = ''
        GREEN = ''
        YELLOW = ''
        CYAN = ''
        RESET = ''
    class Style:
        BRIGHT = ''
        RESET_ALL = ''

def banner():
    print(Fore.CYAN + Style.BRIGHT + r'''
   __     ___   _  __   ____                 
   \ \   / / | | |/ _| |  _ \ __ _ _ __ ___  
    \ \ / /| |_| | |_  | |_) / _` | '_ ` _ \ 
     \ V / |  _  |  _| |  __/ (_| | | | | | |
      \_/  |_| |_|_|   |_|   \__,_|_| |_| |_|
    ''')
    print(Fore.YELLOW + Style.BRIGHT + "🔒 VulXscan - Cyber Tools for Everyone")
    print(Fore.YELLOW + "-" * 50)

def menu():
    print(Fore.YELLOW + "\nSelect an option:\n")
    print("[1] Port Scanner")
    print("[2] Security Headers Checker")
    print("[3] SSL Info Fetcher")
    print("[4] Phishing Awareness Quiz")
    print("[5] Simple Hash Cracker (MD5, SHA1)")
    print("[6] Password Strength Checker")
    print("[7] IP Geolocation Lookup")
    print("[8] Exit")

def port_scanner():
    target = input("Enter IP or domain (without http): ").strip()
    common_ports = [21,22,23,25,53,80,110,139,143,443,445,3389]
    print(f"\n[🔍] Scanning common ports on {target}")
    for port in common_ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.7)
        try:
            result = sock.connect_ex((target, port))
            if result == 0:
                print(Fore.GREEN + f"[✅] Port {port} is OPEN")
            else:
                print(Fore.RED + f"[❌] Port {port} is closed")
            sock.close()
        except Exception as e:
            print(Fore.RED + f"[❌] Error on port {port}: {e}")

def headers_checker():
    url = input("Enter URL (with http/https): ").strip()
    try:
        r = requests.get(url, timeout=6)
        headers = r.headers
        print(f"\n[🧠] Security headers for {url}:")
        important = {
            "X-Content-Type-Options": "Prevents MIME sniffing",
            "X-Frame-Options": "Prevents Clickjacking",
            "Content-Security-Policy": "Controls resources the page can load",
            "Strict-Transport-Security": "Forces HTTPS"
        }
        for header, desc in important.items():
            if header in headers:
                print(Fore.GREEN + f"[✅] {header} is present — {desc}")
            else:
                print(Fore.RED + f"[❌] {header} is MISSING — {desc}")
    except Exception as e:
        print(Fore.RED + f"[❌] Error fetching headers: {e}")

def ssl_info():
    hostname = input("Enter domain (without http): ").strip()
    port = 443
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                print(Fore.CYAN + f"\n[🔐] SSL Certificate info for {hostname}:")
                print(f"Issuer: {cert['issuer']}")
                print(f"Valid from: {cert['notBefore']}")
                print(f"Valid until: {cert['notAfter']}")
                print(f"Subject: {cert['subject']}")
    except Exception as e:
        print(Fore.RED + f"[❌] Failed to get SSL info: {e}")

def phishing_quiz():
    questions = [
        {
            "email": """From: support@paypa1.com
Subject: Urgent - Account locked
Body: Click the link http://paypa1.com/verify to unlock your account.""",
            "answer": "phishing",
            "explanation": "Paypa1.com is not PayPal; watch out for '1' instead of 'l'."
        },
        {
            "email": """From: no-reply@github.com
Subject: Password Changed
Body: Your password has been successfully changed.""",
            "answer": "legit",
            "explanation": "Official GitHub notification, no suspicious links."
        },
        {
            "email": """From: admin@bank-secure.com
Subject: Confirm your account
Body: Please login at https://bank-secure.com/login to verify.""",
            "answer": "phishing",
            "explanation": "The domain is suspicious; real bank URLs don’t usually have 'bank-secure'."
        },
    ]
    score = 0
    print("\nPhishing Awareness Quiz:\n")
    for i, q in enumerate(questions):
        print(Fore.YELLOW + f"Email #{i+1}:\n{q['email']}\n")
        ans = input("Is this Legit or Phishing? (type legit/phishing): ").strip().lower()
        if ans == q["answer"]:
            print(Fore.GREEN + "Correct! " + q["explanation"] + "\n")
            score += 1
        else:
            print(Fore.RED + "Wrong! " + q["explanation"] + "\n")
    print(Fore.CYAN + f"Your score: {score}/{len(questions)}")

def hash_cracker():
    print("\nSimple Hash Cracker (only MD5 and SHA1 with small wordlist)\n")
    hash_input = input("Enter the hash to crack: ").strip()
    htype = ""
    if len(hash_input) == 32:
        htype = "md5"
    elif len(hash_input) == 40:
        htype = "sha1"
    else:
        print(Fore.RED + "Only MD5 and SHA1 hashes supported.")
        return
    # Small demo wordlist
    wordlist = ["password", "123456", "qwerty", "letmein", "admin", "welcome"]
    for word in wordlist:
        if htype == "md5":
            h = hashlib.md5(word.encode()).hexdigest()
        else:
            h = hashlib.sha1(word.encode()).hexdigest()
        if h == hash_input:
            print(Fore.GREEN + f"[✅] Hash cracked! Plain text: '{word}'")
            return
    print(Fore.RED + "[❌] Hash NOT cracked with small wordlist.")

def password_strength():
    pwd = input("Enter a password to check strength: ")
    length = len(pwd)
    score = 0
    if length >= 8:
        score += 1
    if any(c.isdigit() for c in pwd):
        score += 1
    if any(c.isupper() for c in pwd):
        score += 1
    if any(c in "!@#$%^&*()-_+=<>?" for c in pwd):
        score += 1
    print("\nPassword Strength:")
    if score <= 1:
        print(Fore.RED + "Weak password")
    elif score == 2:
        print(Fore.YELLOW + "Moderate password")
    else:
        print(Fore.GREEN + "Strong password")

def ip_geolocation():
    ip = input("Enter IP address: ").strip()
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
        data = r.json()
        if data['status'] == 'success':
            print(Fore.CYAN + f"\nGeolocation info for {ip}:")
            print(f"Country: {data['country']}")
            print(f"Region: {data['regionName']}")
            print(f"City: {data['city']}")
            print(f"ISP: {data['isp']}")
            print(f"Org: {data['org']}")
            print(f"Timezone: {data['timezone']}")
        else:
            print(Fore.RED + f"Error: {data['message']}")
    except Exception as e:
        print(Fore.RED + f"Error fetching geolocation: {e}")

def main():
    while True:
        banner()
        menu()
        choice = input("\nEnter choice (1-8): ").strip()
        if choice == "1":
            port_scanner()
        elif choice == "2":
            headers_checker()
        elif choice == "3":
            ssl_info()
        elif choice == "4":
            phishing_quiz()
        elif choice == "5":
            hash_cracker()
        elif choice == "6":
            password_strength()
        elif choice == "7":
            ip_geolocation()
        elif choice == "8":
            print(Fore.GREEN + "\n[✔️] Exiting VulXscan. Stay secure!")
            break
        else:
            print(Fore.RED + "\n[❌] Invalid choice. Try again.")

if __name__ == "__main__":
    main()
