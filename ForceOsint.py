import socket
import requests
import os
from termcolor import colored
from time import sleep

def banner():
    os.system("clear" if os.name == "posix" else "cls")
    print(colored(r"""
  ______                  ____      _       _    
 |  ____|                / __ \    (_)     | |   
 | |__ ___  _ __ ___ ___| |  | |___ _ _ __ | |_  
 |  __/ _ \| '__/ __/ _ \ |  | / __| | '_ \| __| 
 | | | (_) | | | (_|  __/ |__| \__ \ | | | | |_  
 |_|  \___/|_|  \___\___|\____/|___/_|_| |_|\__| 
                                                 
                                                 
    """, "red"))
    print(colored("☠ FORCEOSİNT - by CyberForceTeam", "red", attrs=["bold"]))
    print(colored("Open Source Intelligence Tool | v1.1", "red"))
    print(colored("⚠ EĞİTİM AMAÇLIDIR! İzinsiz kullanım suçtur.\n", "red", attrs=["bold"]))

def menu():
    print(colored("SEÇENEKLER:", "red", attrs=["bold"]))
    print(colored("""
[1] Site IP Adresi Al
[2] HTTP Header Bilgisi
[3] WHOIS Bilgisi
[4] DNS Lookup
[5] GeoIP (Konum Bilgisi)
[6] Tüm Bilgileri Çek (Otomatik)
[0] Çıkış
""", "red"))

def ip_lookup(domain):
    try:
        ip = socket.gethostbyname(domain)
        print(colored(f"\n[+] IP Adresi: {ip}", "red"))
    except:
        print(colored("[!] IP alınamadı.", "red"))

def headers(domain):
    try:
        r = requests.get("http://" + domain)
        print(colored("\n[+] HTTP Headers:", "red"))
        for k, v in r.headers.items():
            print(colored(f"    {k}: {v}", "red"))
    except:
        print(colored("[!] Header bilgisi alınamadı.", "red"))

def geoip(domain):
    try:
        ip = socket.gethostbyname(domain)
        r = requests.get(f"http://ip-api.com/json/{ip}").json()
        print(colored("\n[+] Konum Bilgisi:", "red"))
        print(colored(f"    Ülke: {r['country']}", "red"))
        print(colored(f"    Şehir: {r['city']}", "red"))
        print(colored(f"    ISP: {r['isp']}", "red"))
        print(colored(f"    Organizasyon: {r['org']}", "red"))
    except:
        print(colored("[!] Konum bilgisi alınamadı.", "red"))

def whois(domain):
    try:
        print(colored("\n[+] WHOIS Bilgisi:", "red"))
        r = requests.get(f"https://rdap.org/domain/{domain}")
        if r.status_code == 200:
            data = r.json()
            print(colored(f"    Domain: {data.get('ldhName', 'Bilinmiyor')}", "red"))
            print(colored(f"    Durum: {', '.join(data.get('status', []))}", "red"))
            print(colored(f"    Oluşturulma: {data.get('events', [{}])[0].get('eventDate', 'N/A')}", "red"))
            print(colored(f"    Registrar: {data.get('registrar', {}).get('name', 'Bilinmiyor')}", "red"))
        else:
            print(colored("    WHOIS bilgisi alınamadı!", "red"))
    except:
        print(colored("[!] WHOIS bilgisi alınamadı.", "red"))

def dns(domain):
    try:
        print(colored("\n[+] DNS Kayıtları:", "red"))
        r = requests.get(f"https://api.hackertarget.com/dnslookup/?q={domain}")
        print(colored(r.text.strip(), "red"))
    except:
        print(colored("[!] DNS kayıtları alınamadı.", "red"))

def main():
    while True:
        banner()
        menu()
        secim = input(colored("Seçenek gir: ", "red")).strip()

        if secim == "0":
            print(colored("Çıkılıyor...", "red"))
            break

        if secim in ["1", "2", "3", "4", "5", "6"]:
            domain = input(colored("Hedef domain gir (örnek: example.com): ", "red")).strip()

        if secim == "1":
            ip_lookup(domain)
        elif secim == "2":
            headers(domain)
        elif secim == "3":
            whois(domain)
        elif secim == "4":
            dns(domain)
        elif secim == "5":
            geoip(domain)
        elif secim == "6":
            ip_lookup(domain)
            headers(domain)
            whois(domain)
            dns(domain)
            geoip(domain)
        else:
            if secim not in ["00", "1", "2", "3", "4", "5", "6"]:
                print(colored("Geçersiz seçenek!", "red"))

        input(colored("\nDevam etmek için Enter'a bas...", "red"))

if __name__ == "__main__":
    main()
