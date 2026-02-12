import requests
import re
import socket
import concurrent.futures
import time
from datetime import datetime
import json
import os

# ИСТОЧНИКИ
SOURCES = [
    "https://raw.githubusercontent.com/hookzof/socks5_list/master/tg/mtproto.json",
    "https://raw.githubusercontent.com/Anonym0usWork1221/Free-Proxies/main/proxy_files/mtproto_proxies.txt",
    "https://raw.githubusercontent.com/officialputuid/KangProxy/KangProxy/mtproto/mtproto.json",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/MTPROTO_RAW.txt",
    "https://raw.githubusercontent.com/yemixzy/proxy-projects/main/proxies/mtproto.txt",
    "https://raw.githubusercontent.com/zevtyardt/proxy-list/main/mtproto.txt",
    "https://raw.githubusercontent.com/prxchk/proxy-list/main/mtproto.txt",
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/mtproto.txt",
    "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-mtproto.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/main/proxies/mtproto.txt",
    "https://raw.githubusercontent.com/devho3ein/tg-proxy/main/mtproto.json"
]

TIMEOUT = 2.0
MAX_WORKERS = 150

RU_DOMAINS = [
    '.ru', 'yandex', 'vk.com', 'mail.ru', 'ok.ru', 'dzen', 'rutube',
    'sber', 'tinkoff', 'vtb', 'gosuslugi', 'nalog', 'mos.ru', 
    'ozon', 'wildberries', 'avito', 'kinopoisk', 'mts', 'beeline'
]

BLOCKED = ['instagram', 'facebook', 'twitter', 'bbc', 'meduza', 'linkedin', 'torproject']

def get_proxies_from_text(text):
    proxies = set()
    
    # Попытка парсить JSON
    if text.strip().startswith('[') or text.strip().startswith('{'):
        try:
            data = json.loads(text)
            if isinstance(data, list):
                for item in data:
                    if isinstance(item, dict):
                        host = item.get('host') or item.get('server')
                        port = item.get('port')
                        secret = item.get('secret')
                        if host and port and secret:
                            proxies.add((host, int(port), str(secret)))
        except:
            pass
    
    # Regex паттерны
    regex = r'(?:server|host)=([^&\s]+).*(?:port)=?(\d+).*(?:secret)=([a-fA-F0-9]{32,})'
    for h, p, s in re.findall(regex, text, re.IGNORECASE):
        proxies.add((h, int(p), s))
    
    regex_simple = r'([a-zA-Z0-9.-]+):(\d+):([a-fA-F0-9]{32,})'
    for h, p, s in re.findall(regex_simple, text):
        proxies.add((h, int(p), s))
    
    return proxies

def decode_domain(secret):
    if not secret.startswith('ee'): return None
    try:
        chars = []
        for i in range(2, len(secret), 2):
            val = int(secret[i:i+2], 16)
            if val == 0: break
            chars.append(chr(val))
        return "".join(chars).lower()
    except: return None

def check_proxy(p):
    host, port, secret = p
    domain = decode_domain(secret)
    
    if len(secret) < 32: return None
    if domain:
        for b in BLOCKED: 
            if b in domain: return None

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(TIMEOUT)
        start = time.time()
        s.connect((host, port))
        ping = time.time() - start
        s.close()
    except: return None

    region = 'eu'
    if domain:
        for r in RU_DOMAINS:
            if r in domain:
                region = 'ru'
                break
                
    return {'link': f"tg://proxy?server={host}&port={port}&secret={secret}", 'ping': ping, 'region': region}

def main():
    start_time = time.time()
    print("🚀 Start collecting...")
    all_raw = set()
    
    for url in SOURCES:
        try:
            r = requests.get(url, timeout=10)
            extracted = get_proxies_from_text(r.text)
            all_raw.update(extracted)
            print(f"✓ {url.split('/')[5]} -> {len(extracted)}")
        except: 
            print(f"✗ Failed: {url.split('/')[5]}")

    print(f"\n⚡ Checking {len(all_raw)} proxies...")
    valid = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as exc:
        futures = {exc.submit(check_proxy, p): p for p in all_raw}
        for f in concurrent.futures.as_completed(futures):
            res = f.result()
            if res: valid.append(res)
            
    ru = sorted([x for x in valid if x['region'] == 'ru'], key=lambda x: x['ping'])
    eu = sorted([x for x in valid if x['region'] == 'eu'], key=lambda x: x['ping'])
    
    # Сохраняем прокси
    with open('proxy_ru.txt', 'w') as f: 
        f.write(f"# RU Proxies ({len(ru)})\n")
        f.write(f"# Updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}\n\n")
        f.write('\n'.join([x['link'] for x in ru]))
        
    with open('proxy_eu.txt', 'w') as f: 
        f.write(f"# EU Proxies ({len(eu)})\n")
        f.write(f"# Updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}\n\n")
        f.write('\n'.join([x['link'] for x in eu]))
        
    with open('proxy_all.txt', 'w') as f: 
        f.write(f"# All Proxies ({len(valid)})\n")
        f.write(f"# Updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}\n\n")
        f.write('\n'.join([x['link'] for x in valid]))
    
    # Создаем статистику
    stats = {
        'updated': datetime.now().isoformat(),
        'total': len(valid),
        'ru_count': len(ru),
        'eu_count': len(eu),
        'sources_checked': len(SOURCES),
        'proxies_checked': len(all_raw),
        'execution_time': round(time.time() - start_time, 2),
        'best_ru_ping': round(ru[0]['ping'], 3) if ru else None,
        'best_eu_ping': round(eu[0]['ping'], 3) if eu else None
    }
    
    with open('proxy_stats.json', 'w') as f:
        json.dump(stats, f, indent=2)
    
    # Удаляем старый файл
    if os.path.exists("proxy_list.txt"):
        os.remove("proxy_list.txt")
        
    print(f"\n✅ DONE: RU={len(ru)}, EU={len(eu)}, TOTAL={len(valid)}")
    print(f"⏱ Time: {stats['execution_time']}s")

if __name__ == "__main__":
    main()
