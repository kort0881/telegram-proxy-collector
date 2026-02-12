import requests
import re
import socket
import concurrent.futures
import time
from urllib.parse import urlparse, parse_qs
from collections import Counter
import logging
import json
from datetime import datetime

# Настройка логирования
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# ОБНОВЛЕННЫЕ РАБОЧИЕ ИСТОЧНИКИ (2026)
SOURCES = [
    "https://raw.githubusercontent.com/hookzof/socks5_list/master/tg/mtproto.json",
    "https://raw.githubusercontent.com/Anonym0usWork1221/Free-Proxies/main/proxy_files/mtproto_proxies.txt",
    "https://raw.githubusercontent.com/officialputuid/KangProxy/KangProxy/mtproto/mtproto.json",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/MTPROTO_RAW.txt",
    "https://raw.githubusercontent.com/yemixzy/proxy-projects/main/proxies/mtproto.txt",
    "https://raw.githubusercontent.com/zevtyardt/proxy-list/main/mtproto.txt",
    "https://raw.githubusercontent.com/prxchk/proxy-list/main/mtproto.txt"
]

# Файлы для сохранения
OUTPUT_RU = "proxy_ru.txt"
OUTPUT_EU = "proxy_eu.txt"
OUTPUT_ALL = "proxy_all.txt"
OUTPUT_STATS = "proxy_stats.json"

# Параметры
TIMEOUT = 3
MAX_WORKERS = 150
MIN_RESPONSE_TIME = 0.01
MAX_RESPONSE_TIME = 2.5

# Классификация доменов
RU_DOMAINS = [
    '.ru', 'yandex', 'vk.com', 'mail.ru', 'sber', 'tinkoff', 'ozon', 
    'wildberries', 'gosuslugi', 'mos.ru', 'nalog', 'avito'
]

EU_DOMAINS = [
    'google', 'cloudflare', 'amazon', 'microsoft', 'azure', 'aws',
    '.com', '.net', '.org', '.eu', '.de', '.fr', '.uk', 'github'
]

# Кэш
checked_hosts = {}

class ProxyClassifier:
    @staticmethod
    def clean_domain(raw_domain):
        """Очищает домен от мусорных символов"""
        # Оставляем только a-z, 0-9, точки и дефисы
        clean = re.sub(r'[^a-zA-Z0-9.-]', '', raw_domain)
        # Убираем точки в начале/конце
        clean = clean.strip('.')
        # Проверяем валидность (минимум одна точка, длина > 3)
        if '.' in clean and len(clean) > 3:
            return clean.lower()
        return None

    @staticmethod
    def decode_secret_domain(secret):
        """Улучшенное извлечение домена из Fake-TLS"""
        if not secret or not secret.startswith('ee'):
            return None
        try:
            # Fake-TLS секрет: ee + hex(domain) + ...
            # Берем hex часть (пропускаем 'ee')
            hex_part = secret[2:]
            
            # Пытаемся декодировать пока не встретим ошибку или null-byte
            decoded_chars = []
            for i in range(0, len(hex_part), 2):
                try:
                    byte_val = int(hex_part[i:i+2], 16)
                    # Если встретили 0 (конец строки) или непечатный символ (кроме . - _)
                    if byte_val == 0:
                        break
                    char = chr(byte_val)
                    if char.isprintable():
                        decoded_chars.append(char)
                    else:
                        break # Останавливаемся на первом мусоре
                except:
                    break
            
            raw_domain = "".join(decoded_chars)
            return ProxyClassifier.clean_domain(raw_domain)
            
        except:
            return None

    @staticmethod
    def classify_by_domain(domain):
        if not domain: return 'unknown'
        for d in RU_DOMAINS:
            if d in domain: return 'ru'
        for d in EU_DOMAINS:
            if d in domain: return 'eu'
        return 'other'

    @staticmethod
    def get_quality_score(secret, region):
        score = 0
        if secret.startswith("ee"):
            score += 20
            if region == 'ru': score += 50
            elif region == 'eu': score += 30
        elif secret.startswith("dd"):
            score += 10
        return score

def parse_proxy(line):
    # Универсальный Regex для tg://, t.me и строк
    patterns = [
        r'server=([^&]+)&port=(\d+)&secret=([a-fA-F0-9]+)',
        r'([a-zA-Z0-9.-]+):(\d+):([a-fA-F0-9]+)'
    ]
    for p in patterns:
        match = re.search(p, line)
        if match:
            return match.group(1), int(match.group(2)), match.group(3)
    return None

def check_proxy(proxy_data):
    host, port, secret = proxy_data
    cache_key = f"{host}:{port}"
    
    if cache_key in checked_hosts: return checked_hosts[cache_key]
    
    # 1. Фильтр секрета
    if not secret or len(secret) < 20: return None # Короткие секреты - мусор
    if not (secret.startswith("ee") or secret.startswith("dd")): return None

    # 2. Проверка порта
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)
        start = time.time()
        res = sock.connect_ex((host, port))
        ping = time.time() - start
        sock.close()
        
        if res != 0 or ping > MAX_RESPONSE_TIME: return None
    except: return None

    # 3. Классификация
    domain = ProxyClassifier.decode_secret_domain(secret)
    region = ProxyClassifier.classify_by_domain(domain)
    score = ProxyClassifier.get_quality_score(secret, region)

    res = {
        'link': f"tg://proxy?server={host}&port={port}&secret={secret}",
        'host': host,
        'ping': ping,
        'score': score,
        'region': region,
        'domain': domain or 'unknown'
    }
    checked_hosts[cache_key] = res
    return res

def process_source(url):
    proxies = []
    try:
        resp = requests.get(url, timeout=10)
        if url.endswith('.json'):
            try:
                data = resp.json()
                # Поддержка разных форматов JSON
                items = data if isinstance(data, list) else data.get('proxies', [])
                for item in items:
                    h = item.get('host') or item.get('server') or item.get('ip')
                    p = item.get('port')
                    s = item.get('secret')
                    if h and p and s: proxies.append((h, int(p), s))
            except: pass
        
        # Текстовый парсинг (всегда пробуем, даже если JSON упал)
        for line in resp.text.splitlines():
            p = parse_proxy(line)
            if p: proxies.append(p)
            
        logger.info(f"✓ {url}: {len(proxies)} шт.")
    except Exception as e:
        logger.warning(f"✗ {url}: {e}")
    return proxies

def main():
    print("🚀 START...")
    
    # 1. Сбор
    all_p = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
        futures = [ex.submit(process_source, url) for url in SOURCES]
        for f in concurrent.futures.as_completed(futures):
            all_p.extend(f.result())
            
    unique = {f"{p[0]}:{p[1]}": p for p in all_p}.values()
    print(f"📊 Уникальных: {len(unique)}")
    
    # 2. Проверка
    valid = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        futures = {ex.submit(check_proxy, p): p for p in unique}
        completed = 0
        for f in concurrent.futures.as_completed(futures):
            completed += 1
            if completed % 100 == 0: print(f"Checking: {completed}/{len(unique)}...", end='\r')
            res = f.result()
            if res: valid.append(res)
            
    print("\n✅ Done!")
    
    # 3. Сохранение
    ru = [p for p in valid if p['region'] == 'ru']
    eu = [p for p in valid if p['region'] == 'eu']
    
    # Сортировка: Сначала высокий рейтинг, потом быстрый пинг
    valid.sort(key=lambda x: (-x['score'], x['ping']))
    ru.sort(key=lambda x: x['ping'])
    
    def save(name, lst):
        with open(name, 'w') as f:
            f.write('\n'.join([p['link'] for p in lst]))
            
    save(OUTPUT_RU, ru)
    save(OUTPUT_EU, eu)
    save(OUTPUT_ALL, valid)
    
    # Статистика
    print(f"\n🇷🇺 RU: {len(ru)} шт.")
    top_ru = Counter([p['domain'] for p in ru]).most_common(5)
    for d, c in top_ru: print(f"  - {d}: {c}")

if __name__ == "__main__":
    main()
