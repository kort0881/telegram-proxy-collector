import requests
import re
import socket
import concurrent.futures
import time
from datetime import datetime
import json
import os
from urllib.parse import urlparse, parse_qs

# ИСТОЧНИКИ (Максимальный охват)
SOURCES = [
    # Основные активные источники
    "https://raw.githubusercontent.com/hookzof/socks5_list/master/tg/mtproto.json",
    "https://raw.githubusercontent.com/soroushmirzaei/telegram-proxies-collector/main/proxies.txt",
    "https://raw.githubusercontent.com/MrPotat-00/MTProtoProxiesScraper/main/proxies.txt",
    
    # Дополнительные источники
    "https://raw.githubusercontent.com/Anonym0usWork1221/Free-Proxies/main/proxy_files/mtproto_proxies.txt",
    "https://raw.githubusercontent.com/officialputuid/KangProxy/KangProxy/mtproto/mtproto.json",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/MTPROTO_RAW.txt",
    "https://raw.githubusercontent.com/yemixzy/proxy-projects/main/proxies/mtproto.txt",
    "https://raw.githubusercontent.com/zevtyardt/proxy-list/main/mtproto.txt",
    "https://raw.githubusercontent.com/prxchk/proxy-list/main/mtproto.txt",
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/mtproto.txt",
    "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-mtproto.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/main/proxies/mtproto.txt",
    "https://raw.githubusercontent.com/devho3ein/tg-proxy/main/mtproto.json",
    "https://raw.githubusercontent.com/zloi-user/hideip.me/main/proxy.txt",
    "https://raw.githubusercontent.com/DigneZzZ/telegram-mtproto-proxies/master/proxy_list.txt",
    "https://raw.githubusercontent.com/ObcbO/getproxy/master/proxy.txt",
]

TIMEOUT = 2.5  # Чуть больше для стабильности
MAX_WORKERS = 200  # Больше потоков

# Расширенные RU домены
RU_DOMAINS = [
    '.ru', '.рф', '.su', 'yandex', 'vk.com', 'mail.ru', 'ok.ru', 'dzen', 'rutube',
    'sber', 'tinkoff', 'alfabank', 'vtb', 'gazprom', 'rosneft', 'lukoil',
    'gosuslugi', 'nalog', 'mos.ru', 'government.ru', 'kremlin',
    'ozon', 'wildberries', 'avito', 'cian', 'dns-shop', 'mvideo', 'eldorado',
    'kinopoisk', 'ivi.ru', 'okko', 'megogo', 'more.tv',
    'mts', 'beeline', 'megafon', 'tele2', 'rostelecom',
    'hh.ru', 'superjob', 'rabota.ru', 'zarplata',
    'rbc.ru', 'lenta.ru', 'ria.ru', 'tass.ru', 'kommersant',
    '1c.ru', 'bitrix', 'kaspersky', 'drweb', 'eset',
    'rzd.ru', 'aeroflot', 's7', 'pobeda', 'utair',
    'delivery-club', 'yandex.eda', 'samokat',
]

# Блокированные домены (пропускаем эти прокси)
BLOCKED = [
    'instagram', 'facebook', 'twitter', 'x.com', 'bbc', 'meduza', 
    'linkedin', 'torproject', 'telegram.org', 'discord', 
    'netflix', 'spotify', 'tiktok', 'reddit'
]

def get_proxies_from_text(text):
    """Улучшенный парсер для всех форматов"""
    proxies = set()
    
    # 1. Попытка парсить как JSON
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
    
    # 2. tg:// и t.me формат
    tg_regex = r'(?:tg://|t\.me/)proxy\?([^\s]+)'
    for params_str in re.findall(tg_regex, text):
        params = parse_qs(params_str)
        if 'server' in params and 'port' in params and 'secret' in params:
            proxies.add((params['server'][0], int(params['port'][0]), params['secret'][0]))
    
    # 3. Общий regex для разных форматов
    patterns = [
        # server=X&port=Y&secret=Z
        r'(?:server|host)=([^&\s]+)[&\s]+(?:port)=(\d+)[&\s]+(?:secret)=([a-fA-F0-9]{32,})',
        # X:Y:Z формат
        r'^([a-zA-Z0-9\.\-]+)[:\|](\d+)[:\|]([a-fA-F0-9]{32,})',
        # JSON-like в строке
        r'"(?:server|host)"\s*:\s*"([^"]+)".*?"port"\s*:\s*(\d+).*?"secret"\s*:\s*"([a-fA-F0-9]{32,})"',
    ]
    
    for pattern in patterns:
        for match in re.findall(pattern, text, re.MULTILINE | re.IGNORECASE):
            try:
                host, port, secret = match
                if 1 <= int(port) <= 65535 and len(secret) >= 32:
                    proxies.add((host, int(port), secret))
            except:
                continue
    
    return proxies

def decode_domain(secret):
    """Декодирование домена из Fake-TLS секрета"""
    if not secret or not secret.startswith('ee'):
        return None
    try:
        chars = []
        hex_part = secret[2:]
        
        # Декодируем по 2 символа
        for i in range(0, len(hex_part), 2):
            if i + 1 >= len(hex_part):
                break
            byte_val = int(hex_part[i:i+2], 16)
            if byte_val == 0:  # null terminator
                break
            if 32 <= byte_val <= 126:  # printable ASCII
                chars.append(chr(byte_val))
        
        domain = "".join(chars).lower()
        # Базовая валидация домена
        if domain and '.' in domain and len(domain) > 3:
            return domain
    except:
        pass
    return None

def check_proxy(p):
    """Проверка прокси с улучшенной логикой"""
    host, port, secret = p
    
    # Базовые фильтры
    if len(secret) < 32:
        return None
    
    # Только ee (Fake-TLS) и dd (Random padding)
    if not (secret.startswith('ee') or secret.startswith('dd')):
        return None
    
    # Декодируем домен
    domain = decode_domain(secret) if secret.startswith('ee') else None
    
    # Проверка на блокированные домены
    if domain:
        for blocked in BLOCKED:
            if blocked in domain:
                return None
    
    # Проверка подключения
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)
        start = time.time()
        sock.connect((host, port))
        ping = round((time.time() - start) * 1000)  # в миллисекундах
        sock.close()
        
        # Защита от фейковых супер-быстрых
        if ping < 5:
            return None
            
    except:
        return None
    
    # Определение региона
    region = 'eu'
    priority = 0
    
    if domain:
        # Проверка на RU домен
        for ru_pattern in RU_DOMAINS:
            if ru_pattern in domain:
                region = 'ru'
                # Приоритет для популярных RU сервисов
                if any(x in domain for x in ['yandex', 'vk.', 'sber', 'gosuslugi']):
                    priority = 10
                else:
                    priority = 5
                break
        
        # Проверка на качественные EU домены
        if region == 'eu':
            if any(x in domain for x in ['cloudflare', 'google', 'microsoft', 'amazon']):
                priority = 3
    
    return {
        'link': f"tg://proxy?server={host}&port={port}&secret={secret}",
        'ping': ping,
        'region': region,
        'priority': priority,
        'domain': domain or 'unknown'
    }

def save_with_header(filename, proxies, title):
    """Сохранение с красивым заголовком"""
    with open(filename, 'w', encoding='utf-8') as f:
        f.write(f"# {title}\n")
        f.write(f"# Updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"# Count: {len(proxies)}\n")
        f.write("#" + "="*50 + "\n\n")
        for p in proxies:
            f.write(p['link'] + '\n')

def main():
    print("\n" + "="*60)
    print("🚀 MTProto Proxy Collector v2.0")
    print("="*60 + "\n")
    
    # Сбор прокси
    all_raw = {}  # Используем dict для дедупликации по host:port
    total_found = 0
    
    print(f"📡 Loading from {len(SOURCES)} sources...")
    for i, url in enumerate(SOURCES, 1):
        try:
            r = requests.get(url, timeout=10, headers={
                'User-Agent': 'Mozilla/5.0 (compatible; ProxyCollector/2.0)'
            })
            extracted = get_proxies_from_text(r.text)
            
            # Дедупликация по host:port
            for host, port, secret in extracted:
                key = f"{host}:{port}"
                # Берем самый длинный секрет (обычно лучше)
                if key not in all_raw or len(secret) > len(all_raw[key][2]):
                    all_raw[key] = (host, port, secret)
            
            print(f"  [{i:2}/{len(SOURCES)}] ✓ Found {len(extracted)} proxies")
            total_found += len(extracted)
        except Exception as e:
            print(f"  [{i:2}/{len(SOURCES)}] ✗ Failed: {url.split('/')[5]}")
    
    unique_proxies = list(all_raw.values())
    print(f"\n📊 Total collected: {total_found} → Unique: {len(unique_proxies)}")
    
    # Проверка прокси
    print(f"\n⚡ Checking {len(unique_proxies)} proxies in {MAX_WORKERS} threads...")
    valid = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = list(executor.map(check_proxy, unique_proxies))
        valid = [f for f in futures if f]
    
    # Сортировка: приоритет → пинг
    ru = sorted([x for x in valid if x['region'] == 'ru'], 
                key=lambda x: (-x['priority'], x['ping']))
    eu = sorted([x for x in valid if x['region'] == 'eu'], 
                key=lambda x: (-x['priority'], x['ping']))
    all_sorted = sorted(valid, key=lambda x: (-x['priority'], x['ping']))
    
    # Сохранение
    save_with_header('proxy_ru.txt', ru, '🇷🇺 Russian MTProto Proxies')
    save_with_header('proxy_eu.txt', eu, '🇪🇺 European MTProto Proxies')
    save_with_header('proxy_all.txt', all_sorted, '🌍 All MTProto Proxies')
    
    # Удаляем старый файл
    if os.path.exists("proxy_list.txt"):
        os.remove("proxy_list.txt")
    
    # Статистика
    print("\n" + "="*60)
    print("📊 RESULTS")
    print("="*60)
    print(f"\n🇷🇺 RU Proxies: {len(ru)}")
    if ru:
        avg_ping = sum(p['ping'] for p in ru) / len(ru)
        print(f"   • Avg ping: {avg_ping:.0f}ms")
        print(f"   • Best ping: {ru[0]['ping']}ms ({ru[0]['domain']})")
    
    print(f"\n🇪🇺 EU Proxies: {len(eu)}")
    if eu:
        avg_ping = sum(p['ping'] for p in eu) / len(eu)
        print(f"   • Avg ping: {avg_ping:.0f}ms")
        print(f"   • Best ping: {eu[0]['ping']}ms ({eu[0]['domain']})")
    
    print(f"\n✅ TOTAL: {len(valid)} working proxies")
    print("💾 Saved: proxy_ru.txt, proxy_eu.txt, proxy_all.txt")
    print("="*60 + "\n")

if __name__ == "__main__":
    main()
