import requests
import re
import socket
import concurrent.futures
import time
from datetime import datetime
import json

# АГРЕССИВНЫЙ СПИСОК ИСТОЧНИКОВ
SOURCES = [
    "https://raw.githubusercontent.com/hookzof/socks5_list/master/tg/mtproto.json",
    "https://raw.githubusercontent.com/Anonym0usWork1221/Free-Proxies/main/proxy_files/mtproto_proxies.txt",
    "https://raw.githubusercontent.com/officialputuid/KangProxy/KangProxy/mtproto/mtproto.json",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/MTPROTO_RAW.txt",
    "https://raw.githubusercontent.com/yemixzy/proxy-projects/main/proxies/mtproto.txt",
    "https://raw.githubusercontent.com/zevtyardt/proxy-list/main/mtproto.txt",
    "https://raw.githubusercontent.com/prxchk/proxy-list/main/mtproto.txt",
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/mtproto.txt",
    "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-mtproto.txt"
]

# Настройки
TIMEOUT = 3.0
MAX_WORKERS = 100

# Домены маскировки
RU_DOMAINS = [
    '.ru', 'yandex', 'vk.com', 'mail.ru', 'ok.ru', 'dzen', 'rutube',
    'sber', 'tinkoff', 'vtb', 'gosuslugi', 'nalog', 'mos.ru', 
    'ozon', 'wildberries', 'avito', 'kinopoisk', 'ivi', 'mts', 'beeline'
]

BLOCKED = [
    'instagram', 'facebook', 'twitter', 'bbc', 'dw.com', 
    'meduza', 'svoboda', 'linkedin', 'torproject'
]

def get_proxies_from_text(text):
    """Мощный парсер, ищет любые MTProto ссылки в тексте"""
    proxies = set()
    
    # 1. Поиск ссылок tg://proxy?server=...
    # Ищем любые комбинации server=...&port=...&secret=...
    regex = r'(?:server|host)=([^&\s]+).*(?:port)=?(\d+).*(?:secret)=([a-fA-F0-9]{32,})'
    found = re.findall(regex, text, re.IGNORECASE)
    
    for host, port, secret in found:
        proxies.add((host, int(port), secret))

    # 2. Поиск формата host:port:secret
    regex_simple = r'([a-zA-Z0-9.-]+):(\d+):([a-fA-F0-9]{32,})'
    found_simple = re.findall(regex_simple, text)
    
    for host, port, secret in found_simple:
        proxies.add((host, int(port), secret))
        
    return list(proxies)

def decode_domain(secret):
    """Декодер Fake-TLS"""
    if not secret.startswith('ee'): return None
    try:
        hex_d = secret[2:]
        chars = []
        for i in range(0, len(hex_d), 2):
            val = int(hex_d[i:i+2], 16)
            if val == 0: break
            chars.append(chr(val))
        d = "".join(chars)
        # Очистка
        return re.sub(r'[^a-zA-Z0-9.-]', '', d).lower()
    except: return None

def check_proxy(p):
    host, port, secret = p
    
    # Фильтр секрета
    if len(secret) < 32: return None
    
    # Анализ домена
    domain = decode_domain(secret)
    
    # 1. Сразу выкидываем заблокированные
    if domain:
        for b in BLOCKED:
            if b in domain: return None

    # Проверка порта
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(TIMEOUT)
        start = time.time()
        s.connect((host, port))
        ping = time.time() - start
        s.close()
    except:
        return None

    # Классификация
    region = 'eu'
    if domain:
        for r in RU_DOMAINS:
            if r in domain:
                region = 'ru'
                break
                
    return {
        'link': f"tg://proxy?server={host}&port={port}&secret={secret}",
        'ping': ping,
        'region': region,
        'domain': domain
    }

def main():
    print("🚀 Сбор прокси...")
    
    all_raw = set()
    
    for url in SOURCES:
        try:
            r = requests.get(url, timeout=10)
            if url.endswith('.json'):
                try:
                    # Попытка парсить как JSON
                    data = r.json()
                    # Если это список словарей
                    if isinstance(data, list):
                        for x in data:
                            h = x.get('host') or x.get('server') or x.get('ip')
                            p = x.get('port')
                            s = x.get('secret')
                            if h and p and s: all_raw.add((h, int(p), s))
                except:
                    # Если JSON не вышел, парсим как текст
                    pass
            
            # Всегда парсим как текст (на случай ошибок JSON или текстовых файлов)
            extracted = get_proxies_from_text(r.text)
            for p in extracted:
                all_raw.add(p)
                
            print(f"✓ {url} -> найдено {len(extracted)} (всего {len(all_raw)})")
            
        except Exception as e:
            print(f"✗ Ошибка {url}: {e}")

    print(f"\n⚡ Проверка {len(all_raw)} адресов...")
    
    valid = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as exc:
        futures = {exc.submit(check_proxy, p): p for p in list(all_raw)}
        for f in concurrent.futures.as_completed(futures):
            res = f.result()
            if res: valid.append(res)
            
    # Разделение
    ru_list = [x for x in valid if x['region'] == 'ru']
    eu_list = [x for x in valid if x['region'] == 'eu']
    
    # Сортировка
    ru_list.sort(key=lambda x: x['ping'])
    valid.sort(key=lambda x: x['ping'])
    
    # Сохранение
    with open('proxy_ru.txt', 'w') as f:
        f.write('\n'.join([x['link'] for x in ru_list]))
        
    with open('proxy_eu.txt', 'w') as f:
        f.write('\n'.join([x['link'] for x in eu_list]))
        
    with open('proxy_all.txt', 'w') as f:
        f.write('\n'.join([x['link'] for x in valid]))
        
    print(f"\n✅ ИТОГ:\n🇷🇺 RU: {len(ru_list)}\n🌍 EU: {len(eu_list)}\n📈 ВСЕГО: {len(valid)}")

if __name__ == "__main__":
    main()
