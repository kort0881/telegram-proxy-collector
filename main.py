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

# ==========================================
# 1. ИСТОЧНИКИ (Проверенные GitHub Raw ссылки)
# ==========================================
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

# Параметры проверки
TIMEOUT = 3
MAX_WORKERS = 150
MIN_RESPONSE_TIME = 0.01
MAX_RESPONSE_TIME = 2.5

# ==========================================
# 2. СПИСКИ ДОМЕНОВ (Белые и Черные)
# ==========================================

# ✅ RU Whitelist: Под эти домены маскироваться ЛУЧШЕ всего
RU_DOMAINS = [
    '.ru', 'yandex', 'vk.com', 'mail.ru', 'sber', 'tinkoff', 'ozon', 
    'wildberries', 'gosuslugi', 'mos.ru', 'nalog', 'avito', 'rzd', 'aeroflot'
]

# 🌍 EU Whitelist: Нейтральные глобальные домены
EU_DOMAINS = [
    'google', 'cloudflare', 'amazon', 'microsoft', 'azure', 'aws',
    '.com', '.net', '.org', '.eu', '.de', '.fr', '.uk', 'github'
]

# ⛔ BLACKLIST: Заблокированные в РФ ресурсы
# Если прокси маскируется под них — он будет заблокирован ТСПУ
BLOCKED_DOMAINS = [
    'instagram', 'facebook', 'twitter', 'x.com', 'linkedin',
    'bbc.co', 'dw.com', 'meduza', 'svoboda', 'voiceofamerica',
    'torproject', 'proton', 'tunnelbear', 'windscribe',
    'bet365', 'pokerstars', 'rutracker', 'telegram.org'
]

# Кэш проверенных хостов
checked_hosts = {}

# ==========================================
# 3. КЛАССЫ И ФУНКЦИИ
# ==========================================

class ProxyClassifier:
    @staticmethod
    def clean_domain(raw_domain):
        """Очищает домен от мусорных символов"""
        clean = re.sub(r'[^a-zA-Z0-9.-]', '', raw_domain)
        clean = clean.strip('.')
        if '.' in clean and len(clean) > 3:
            return clean.lower()
        return None

    @staticmethod
    def decode_secret_domain(secret):
        """Декодирует домен из Fake-TLS (ee...)"""
        if not secret or not secret.startswith('ee'):
            return None
        try:
            hex_part = secret[2:]
            decoded_chars = []
            for i in range(0, len(hex_part), 2):
                try:
                    byte_val = int(hex_part[i:i+2], 16)
                    if byte_val == 0: break
                    char = chr(byte_val)
                    if char.isprintable(): decoded_chars.append(char)
                    else: break
                except: break
            
            raw_domain = "".join(decoded_chars)
            return ProxyClassifier.clean_domain(raw_domain)
        except:
            return None

    @staticmethod
    def classify_by_domain(domain):
        """Определяет регион по домену"""
        if not domain: return 'unknown'
        for d in RU_DOMAINS:
            if d in domain: return 'ru'
        for d in EU_DOMAINS:
            if d in domain: return 'eu'
        return 'other'

    @staticmethod
    def get_quality_score(secret, region, domain):
        """Оценка качества прокси"""
        score = 0
        
        # 1. Проверка на BLACKLIST
        if domain:
            for bad in BLOCKED_DOMAINS:
                if bad in domain:
                    return -100  # ⛔ Сразу в мусорку
        
        # 2. Оценка Fake-TLS
        if secret.startswith("ee"):
            score += 20  # База
            if region == 'ru': 
                score += 50  # 🥇 Золото для РФ
            elif region == 'eu': 
                score += 30  # 🥈 Серебро для мира
        elif secret.startswith("dd"):
            score += 10  # Бронза (Random Padding)
            
        return score

def parse_proxy(line):
    """Парсит строку в кортеж (host, port, secret)"""
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
    """Полная проверка одного прокси"""
    host, port, secret = proxy_data
    cache_key = f"{host}:{port}"
    
    if cache_key in checked_hosts: return checked_hosts[cache_key]
    
    # 1. Фильтр секрета
    if not secret or len(secret) < 20: return None
    if not (secret.startswith("ee") or secret.startswith("dd")): return None

    # 2. Декодирование и проверка на Blacklist (до соединения!)
    domain = ProxyClassifier.decode_secret_domain(secret)
    region = ProxyClassifier.classify_by_domain(domain)
    score = ProxyClassifier.get_quality_score(secret, region, domain)
    
    if score < 0: return None  # Пропускаем, если домен в бане

    # 3. Проверка TCP порта
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)
        start = time.time()
        res = sock.connect_ex((host, port))
        ping = time.time() - start
        sock.close()
        
        if res != 0 or ping > MAX_RESPONSE_TIME: return None
    except: return None

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
    """Скачивает и парсит источник"""
    proxies = []
    try:
        resp = requests.get(url, timeout=10)
        # JSON
        if url.endswith('.json'):
            try:
                data = resp.json()
                items = data if isinstance(data, list) else data.get('proxies', [])
                for item in items:
                    h = item.get('host') or item.get('server') or item.get('ip')
                    p = item.get('port')
                    s = item.get('secret')
                    if h and p and s: proxies.append((h, int(p), s))
            except: pass
        
        # Text (fallback)
        for line in resp.text.splitlines():
            p = parse_proxy(line)
            if p: proxies.append(p)
            
        logger.info(f"✓ {url}: {len(proxies)} шт.")
    except Exception as e:
        logger.warning(f"✗ {url}: {e}")
    return proxies

def main():
    print("🚀 START: Запуск коллектора прокси...")
    
    # --- 1. Сбор ---
    all_p = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
        futures = [ex.submit(process_source, url) for url in SOURCES]
        for f in concurrent.futures.as_completed(futures):
            all_p.extend(f.result())
            
    unique = {f"{p[0]}:{p[1]}": p for p in all_p}.values()
    print(f"📊 Найдено уникальных кандидатов: {len(unique)}")
    
    # --- 2. Проверка ---
    valid = []
    print(f"⚡ Начинаю проверку ({MAX_WORKERS} потоков)...")
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        futures = {ex.submit(check_proxy, p): p for p in unique}
        completed = 0
        total = len(unique)
        for f in concurrent.futures.as_completed(futures):
            completed += 1
            if completed % 100 == 0: 
                print(f"Progress: {completed}/{total} ({int(completed/total*100)}%)", end='\r')
            res = f.result()
            if res: valid.append(res)
            
    print(f"\n✅ Проверка завершена. Рабочих: {len(valid)}")
    
    # --- 3. Сортировка и сохранение ---
    ru = [p for p in valid if p['region'] == 'ru']
    eu = [p for p in valid if p['region'] == 'eu']
    
    # Сортировка: сначала высокий Score, потом быстрый Ping
    valid.sort(key=lambda x: (-x['score'], x['ping']))
    ru.sort(key=lambda x: (-x['score'], x['ping'])) # В RU файле тоже сортируем по качеству
    
    def save_file(filename, proxy_list, header):
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(f"# {header} | Updated: {datetime.now().strftime('%Y-%m-%d %H:%M')}\n")
            f.write(f"# Total: {len(proxy_list)}\n\n")
            f.write('\n'.join([p['link'] for p in proxy_list]))
            
    save_file(OUTPUT_RU, ru, "RU Fake-TLS Proxies (High Priority)")
    save_file(OUTPUT_EU, eu, "EU/Global Fake-TLS Proxies")
    save_file(OUTPUT_ALL, valid, "All Valid Proxies")
    
    # --- 4. Статистика (JSON) ---
    stats = {
        'updated': datetime.now().isoformat(),
        'total_valid': len(valid),
        'ru_count': len(ru),
        'eu_count': len(eu),
        'ru_top_domains': dict(Counter([p['domain'] for p in ru]).most_common(10)),
        'eu_top_domains': dict(Counter([p['domain'] for p in eu]).most_common(10))
    }
    with open(OUTPUT_STATS, 'w') as f:
        json.dump(stats, f, indent=2)

    # Вывод в консоль
    print(f"\n🇷🇺 RU Proxies: {len(ru)}")
    for d, c in Counter([p['domain'] for p in ru]).most_common(5):
        print(f"  - {d}: {c}")
        
    print(f"\n💾 Файлы сохранены: {OUTPUT_RU}, {OUTPUT_EU}, {OUTPUT_ALL}")

if __name__ == "__main__":
    main()

