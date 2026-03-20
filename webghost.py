import requests
import argparse
import socket
import ssl
import datetime

def bas():
    uzantı = argparse.ArgumentParser(description="Web Ghost")
    uzantı.add_argument("-S","--scan",help="Example 192.168.1.255 or example.com",required=True)
    args = uzantı.parse_args()
    return args.scan

def tarama(hedef):
    try:
        print("Analyzing target...")
        for port in [80,443]:
            baglantı = ""
            cevap = None
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            site_durumu = s.connect_ex((hedef, port))
            s.close()
            if site_durumu == 0:
                if port == 80:
                    baglantı = "http://" + hedef
                else:
                    baglantı = "https://" + hedef
                cevap = requests.get(baglantı, timeout=3)
                if cevap and cevap.status_code == 200:
                    sunucu = cevap.headers.get('Server', '')
                    sunucu_kontrol = sunucu.lower()
                    if 'nginx' in sunucu_kontrol:
                        print('\n [+] Server: Nginx')
                    elif 'apache' in sunucu_kontrol:
                        print("\n [+] Server: Apache")
                    elif 'microsoft-iis' in sunucu_kontrol:
                        print("\n [+] Server: Microsoft-iis")
                    elif 'cloudflare' in sunucu_kontrol:
                        print("\n [+] Server: Cloudflare")
                    yazılım = cevap.headers.get('X-Powered-By', '')
                    yazılım_kontrol = yazılım.lower()
                    if 'php' in yazılım_kontrol:
                        print('\n [+] Software: PHP')
                    elif 'asp.net' in yazılım_kontrol:
                        print('\n [+] Software: ASP.NET')
                    cerezler = str(cevap.cookies).lower()
                    if 'phpsessid' in cerezler:
                        print('\n [+] Cookies: PHP')
                    elif 'aspsessionid' in cerezler:
                        print('\n [+] Cookies: ASP.NET')
                    elif 'jsessionid' in cerezler:
                        print('\n [+] Cookies: Java')
                    if '/' in sunucu:
                        parcalar = sunucu.split('/')
                        print(f"\n [+] Version: {parcalar[1]}")
                    cevap_robots = requests.get(baglantı + "/robots.txt", timeout=2)
                    if cevap_robots and cevap_robots.status_code == 200:
                        print(f'\n [+] robots.txt')
                        print(20 * '-')
                        print(cevap_robots.text)
                    for yol in ['/wp-login.php', '/administrator', '/user/login']:
                        cevap_yol = requests.get(baglantı + yol, timeout=3)
                        if cevap_yol and cevap_yol.status_code == 200:
                            if 'wp-login' in yol and 'wp-content' in cevap_yol.text:
                                print('\n [+] CMS: WordPress')
                            elif 'administrator' in yol and 'com_login' in cevap_yol.text:
                                print('\n [+] CMS: Joomla')
                            elif 'user/login' in yol and 'drupal' in cevap_yol.text.lower():
                                print('\n [+] CMS: Drupal')
                    for baslık in ['X-Frame-Options', 'X-XSS-Protection', 'Content-Security-Policy', 'Strict-Transport-Security']:
                        degerlik = cevap.headers.get(baslık, '')
                        if degerlik:
                            print(f'\n [+] {baslık}: {degerlik}')
                    for waf in ['X-Sucuri-ID', 'CF-RAY']:
                        waflık = cevap.headers.get(waf, '')
                        if waflık:
                            if 'CF-RAY' in waf:
                                print('\n [+] WAF: Cloudflare')
                            elif 'X-Sucuri-ID' in waf:
                                print('\n [+] WAF: Sucuri')
                    xfirewall = cevap.headers.get('X-Firewall-Protection', '')
                    if xfirewall:
                        print(f'\n [+] WAF: {xfirewall}')
                    xcdn = cevap.headers.get('X-CDN', '')
                    if xcdn:
                        print(f'\n [+] CDN: {xcdn}')
                    if port == 443:
                        context = ssl.create_default_context()
                        conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=hedef)
                        conn.connect((hedef, 443))
                        sertifika = conn.getpeercert()
                        conn.close()
                        bitis = datetime.datetime.strptime(sertifika['notAfter'], '%b %d %H:%M:%S %Y %Z')
                        veren = sertifika['issuer'][1][0][1]
                        print(f'\n [+] SSL Certificate: {veren}')
                        print(f'\n [+] Valid Until: {bitis.strftime("%d/%m/%Y")}')
                    break
    except Exception as e:
        print(f'\n [!] Unexpected error: {e}')

if __name__ == "__main__":
    site = bas()
    tarama(site)