import requests
import re
import socket
import concurrent.futures
import time
from urllib.parse import urlparse, parse_qs
from collections import Counter, defaultdict
import logging
import json
from datetime import datetime
import ipaddress

# Настройка логирования
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Источники
SOURCES = [
    "https://raw.githubusercontent.com/SoliSpirit/mtproto/master/proxies.txt",
    "https://raw.githubusercontent.com/hookzof/socks5_list/master/tg/mtproto.json",
    "https://raw.githubusercontent.com/soroushmirzaei/telegram-proxies-collector/main/proxies.txt",
    "https://raw.githubusercontent.com/MrPotat-00/MTProtoProxiesScraper/main/proxies.txt",
    "https://raw.githubusercontent.com/DigneZzZ/telegram-mtproto-proxies/master/proxy_list.txt",
    "https://raw.githubusercontent.com/zloi-user/hideip.me/main/proxy.txt",
    "https://raw.githubusercontent.com/ErcinDedeoglu/proxies/main/proxies/mtproto.txt",
    "https://raw.githubusercontent.com/ObcbO/getproxy/master/proxy.txt",
    "https://raw.githubusercontent.com/iw4p/MTProtoCollector/main/proxies.txt",
    "https://raw.githubusercontent.com/ALiasGHARBi/MTProtoProxies/main/proxies.txt"
]

# Файлы для сохранения
OUTPUT_RU = "proxy_ru.txt"          # Русские прокси
OUTPUT_EU = "proxy_eu.txt"          # Европейские/глобальные прокси
OUTPUT_ALL = "proxy_all.txt"        # Все прокси
OUTPUT_STATS = "proxy_stats.json"   # Статистика

# Параметры
TIMEOUT = 3
MAX_WORKERS = 150
MIN_RESPONSE_TIME = 0.01
MAX_RESPONSE_TIME = 2.5

# ============ КЛАССИФИКАЦИЯ ДОМЕНОВ ============

# Русские домены и сервисы
RU_DOMAINS = [
    # Домены
    '.ru', '.su', '.рф', '.moscow', '.tatar',
    
    # Крупные сервисы
    'yandex.', 'vk.com', 'vkontakte', 'mail.ru', 'mailru',
    'sberbank', 'tinkoff', 'alfabank', 'vtb.', 'gazprom',
    'ozon.', 'wildberries', 'avito.', 'cian.', 'drom.',
    'gosuslugi', 'nalog.', 'mos.ru', 'government',
    'rzd.', 'aeroflot', 'pochta.', 's7.',
    'kaspersky', 'drweb', '1c.', 'bitrix',
    'rutube', 'okko.', 'ivi.', 'kinopoisk',
    'mts.', 'megafon', 'beeline', 'tele2',
    'lenta.', 'dns-shop', 'mvideo', 'eldorado',
    'hh.ru', 'superjob', 'rabota.',
]

# Европейские домены и сервисы
EU_DOMAINS = [
    # Европейские домены
    '.de', '.fr', '.nl', '.uk', '.it', '.es', '.pl', '.se', 
    '.fi', '.no', '.dk', '.at', '.ch', '.be', '.cz', '.pt',
    '.ie', '.gr', '.hu', '.ro', '.bg', '.sk', '.hr', '.si',
    '.ee', '.lv', '.lt', '.lu', '.cy', '.mt',
    '.eu', '.europa',
    
    # Европейские сервисы и компании
    'hetzner', 'ovh.', 'scaleway', 'contabo',
    'deutsche', 'telefonica', 'orange.', 'vodafone',
    'bbc.', 'guardian', 'spiegel', 'lemonde',
    'airbus', 'siemens', 'bosch', 'bmw', 'mercedes',
    'spotify', 'klarna', 'adyen', 'booking',
]

# Глобальные/CDN домены (будут в EU категории)
GLOBAL_DOMAINS = [
    # CDN и облака
    'cloudflare', 'fastly', 'akamai', 'cloudfront', 'azurefd',
    'googleapis', 'googleusercontent', 'gstatic', 'fbcdn',
    'amazon', 'aws.', 'azure.', 'digitalocean',
    
    # Tech гиганты
    'google.com', 'microsoft.com', 'apple.com', 'meta.com',
    'facebook.com', 'netflix.com', 'github.', 'gitlab',
    'twitter.com', 'x.com', 'instagram', 'whatsapp',
    'zoom.', 'slack.', 'discord.',
    
    # Прочие популярные
    'wikipedia', 'reddit.', 'stackoverflow',
]

# Кэш и blacklist
checked_hosts = {}
blacklist_hosts = set()

class ProxyClassifier:
    """Классификатор прокси по регионам"""
    
    @staticmethod
    def decode_secret_domain(secret):
        """Извлекает домен из Fake-TLS секрета"""
        if not secret or not secret.startswith('ee'):
            return None
        try:
            hex_part = secret[2:]
            if len(hex_part) % 2 != 0:
                hex_part = hex_part[:-1]
            
            # Поиск null-байта
            for i in range(0, len(hex_part), 2):
                if hex_part[i:i+2] == '00':
                    hex_part = hex_part[:i]
                    break
            
            domain_bytes = bytes.fromhex(hex_part)
            domain = domain_bytes.decode('utf-8', errors='ignore')
            domain = ''.join(c for c in domain if c.isprintable())
            
            return domain.lower() if domain else None
        except:
            return None
    
    @staticmethod
    def classify_by_domain(domain):
        """Классифицирует прокси по домену маскировки"""
        if not domain:
            return 'unknown'
        
        domain_lower = domain.lower()
        
        # Проверка на RU
        for ru_pattern in RU_DOMAINS:
            if ru_pattern in domain_lower:
                return 'ru'
        
        # Проверка на EU
        for eu_pattern in EU_DOMAINS:
            if eu_pattern in domain_lower:
                return 'eu'
        
        # Проверка на Global (относим к EU)
        for global_pattern in GLOBAL_DOMAINS:
            if global_pattern in domain_lower:
                return 'eu'
        
        return 'other'
    
    @staticmethod
    def get_quality_score(secret, region):
        """Оценка качества с учетом региона"""
        score = 0
        
        if secret.startswith("ee"):
            score += 20
            domain = ProxyClassifier.decode_secret_domain(secret)
            
            if domain:
                # Бонус за соответствие региону
                if region == 'ru':
                    for ru_pattern in RU_DOMAINS[:15]:  # Топ RU сервисы
                        if ru_pattern in domain.lower():
                            score += 50
                            break
                elif region == 'eu':
                    for eu_pattern in EU_DOMAINS + GLOBAL_DOMAINS:
                        if eu_pattern in domain.lower():
                            score += 30
                            break
                
                if len(secret) > 32:
                    score += 10
                    
        elif secret.startswith("dd"):
            score += 10
            if len(secret) == 34:
                score += 5
        
        return score

def parse_proxy(line):
    """Универсальный парсер прокси"""
    line = line.strip()
    if not line or line.startswith('#'):
        return None
    
    patterns = [
        r'(?:tg://|https?://t\.me/)proxy\?server=([^&]+)&port=(\d+)&secret=([a-fA-F0-9]+)',
        r'["\'](?:server|host)["\']:\s*["\']([^"\']+)["\'].*?["\']port["\']:\s*(\d+).*?["\']secret["\']:\s*["\']([a-fA-F0-9]+)',
        r'^([a-zA-Z0-9\.\-]+):(\d+):([a-fA-F0-9]+)$',
        r'([a-zA-Z0-9\.\-]+)\|(\d+)\|([a-fA-F0-9]+)',
    ]
    
    for pattern in patterns:
        match = re.search(pattern, line, re.IGNORECASE)
        if match:
            try:
                server = match.group(1)
                port = int(match.group(2))
                secret = match.group(3)
                if 1 <= port <= 65535 and len(secret) >= 4:
                    return server, port, secret
            except:
                continue
    
    return None

def check_proxy(proxy_data):
    """Проверка и классификация прокси"""
    host, port, secret = proxy_data
    
    # Кэш
    cache_key = f"{host}:{port}"
    if cache_key in checked_hosts:
        cached = checked_hosts[cache_key]
        if time.time() - cached['time'] < 300:
            return cached['result']
    
    # Blacklist
    if host in blacklist_hosts:
        return None
    
    # Фильтр секрета
    if not secret or len(secret) < 4:
        return None
    if not (secret.startswith("ee") or secret.startswith("dd")):
        return None
    
    # DNS
    try:
        socket.gethostbyname(host)
    except:
        blacklist_hosts.add(host)
        return None
    
    # Проверка порта
    try:
        start_time = time.time()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)
        result = sock.connect_ex((host, port))
        response_time = time.time() - start_time
        sock.close()
        
        if result != 0:
            return None
        if response_time < MIN_RESPONSE_TIME or response_time > MAX_RESPONSE_TIME:
            return None
    except:
        return None
    
    # Классификация
    domain = ProxyClassifier.decode_secret_domain(secret)
    region = ProxyClassifier.classify_by_domain(domain)
    quality_score = ProxyClassifier.get_quality_score(secret, region)
    
    result = {
        'link': f"tg://proxy?server={host}&port={port}&secret={secret}",
        'host': host,
        'port': port,
        'secret': secret,
        'response_time': response_time,
        'quality_score': quality_score,
        'domain': domain or 'unknown',
        'region': region,
        'timestamp': time.time()
    }
    
    checked_hosts[cache_key] = {'result': result, 'time': time.time()}
    return result

def process_source(url):
    """Загрузка и парсинг источника"""
    proxies = []
    
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/plain, application/json, */*',
        }
        
        resp = requests.get(url, timeout=20, headers=headers)
        resp.raise_for_status()
        content = resp.text
        
        # JSON
        if url.endswith('.json') or 'application/json' in resp.headers.get('content-type', ''):
            try:
                data = json.loads(content)
                if isinstance(data, list):
                    for item in data:
                        if isinstance(item, dict):
                            host = item.get('host') or item.get('server')
                            port = item.get('port')
                            secret = item.get('secret')
                            if host and port and secret:
                                proxies.append((host, int(port), secret))
            except:
                pass
        
        # Текст
        for line in content.splitlines():
            parsed = parse_proxy(line)
            if parsed:
                proxies.append(parsed)
        
        if proxies:
            logger.info(f"✓ {url}: {len(proxies)} прокси")
            
    except Exception as e:
        logger.warning(f"✗ {url}: {e}")
    
    return proxies

def save_proxies(proxies, filename, category_name):
    """Сохранение прокси в файл"""
    if not proxies:
        logger.warning(f"⚠ {category_name}: нет прокси для сохранения")
        return
    
    with open(filename, "w", encoding="utf-8") as f:
        f.write(f"# {category_name} MTProto Proxies\n")
        f.write(f"# Обновлено: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"# Количество: {len(proxies)}\n")
        f.write("#" + "=" * 50 + "\n\n")
        
        for p in proxies:
            f.write(p['link'] + "\n")
    
    logger.info(f"💾 {category_name}: сохранено {len(proxies)} в {filename}")

def main():
    start_time = time.time()
    
    print()
    print("=" * 60)
    print("🚀 MTProto Proxy Collector - RU/EU Edition")
    print("=" * 60)
    print()
    
    # === ЭТАП 1: СБОР ===
    logger.info(f"📡 Загрузка из {len(SOURCES)} источников...")
    
    all_candidates = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(process_source, url) for url in SOURCES]
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                all_candidates.extend(result)
    
    # Дедупликация
    unique_map = {}
    for proxy in all_candidates:
        key = f"{proxy[0]}:{proxy[1]}"
        if key not in unique_map:
            unique_map[key] = proxy
    
    candidates = list(unique_map.values())
    logger.info(f"📊 Уникальных кандидатов: {len(candidates)}")
    
    # === ЭТАП 2: ПРОВЕРКА ===
    logger.info(f"⚡ Проверка в {MAX_WORKERS} потоков...")
    
    valid_proxies = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(check_proxy, p): p for p in candidates}
        
        completed = 0
        total = len(futures)
        
        for future in concurrent.futures.as_completed(futures):
            completed += 1
            if completed % 50 == 0 or completed == total:
                pct = completed * 100 // total
                print(f"\r⏳ Прогресс: {completed}/{total} ({pct}%)", end='', flush=True)
            
            try:
                result = future.result(timeout=TIMEOUT + 1)
                if result:
                    valid_proxies.append(result)
            except:
                continue
    
    print()  # Новая строка
    
    if not valid_proxies:
        logger.error("❌ Не найдено рабочих прокси!")
        return
    
    # === ЭТАП 3: КЛАССИФИКАЦИЯ ===
    ru_proxies = [p for p in valid_proxies if p['region'] == 'ru']
    eu_proxies = [p for p in valid_proxies if p['region'] in ('eu', 'other', 'unknown')]
    
    # Сортировка по качеству и скорости
    ru_proxies.sort(key=lambda x: (-x['quality_score'], x['response_time']))
    eu_proxies.sort(key=lambda x: (-x['quality_score'], x['response_time']))
    valid_proxies.sort(key=lambda x: (-x['quality_score'], x['response_time']))
    
    # === ЭТАП 4: СТАТИСТИКА ===
    print()
    print("=" * 60)
    print("📊 РЕЗУЛЬТАТЫ")
    print("=" * 60)
    
    print(f"\n🇷🇺 РУССКИЕ прокси: {len(ru_proxies)}")
    if ru_proxies:
        avg_ping_ru = sum(p['response_time'] for p in ru_proxies) / len(ru_proxies)
        print(f"   • Средний пинг: {avg_ping_ru:.3f}с")
        
        ru_domains = Counter(p['domain'] for p in ru_proxies if p['domain'] != 'unknown')
        if ru_domains:
            print("   • Топ домены:")
            for domain, count in ru_domains.most_common(5):
                print(f"     - {domain}: {count}")
    
    print(f"\n🇪🇺 ЕВРОПЕЙСКИЕ/ГЛОБАЛЬНЫЕ прокси: {len(eu_proxies)}")
    if eu_proxies:
        avg_ping_eu = sum(p['response_time'] for p in eu_proxies) / len(eu_proxies)
        print(f"   • Средний пинг: {avg_ping_eu:.3f}с")
        
        eu_domains = Counter(p['domain'] for p in eu_proxies if p['domain'] != 'unknown')
        if eu_domains:
            print("   • Топ домены:")
            for domain, count in eu_domains.most_common(5):
                print(f"     - {domain}: {count}")
    
    print(f"\n📈 ВСЕГО рабочих: {len(valid_proxies)}")
    
    # === ЭТАП 5: СОХРАНЕНИЕ ===
    print()
    print("=" * 60)
    print("💾 СОХРАНЕНИЕ")
    print("=" * 60)
    
    save_proxies(ru_proxies, OUTPUT_RU, "🇷🇺 RU Proxies")
    save_proxies(eu_proxies, OUTPUT_EU, "🇪🇺 EU/Global Proxies")
    save_proxies(valid_proxies, OUTPUT_ALL, "📋 All Proxies")
    
    # JSON статистика
    stats = {
        'updated': datetime.now().isoformat(),
        'total': len(valid_proxies),
        'ru_count': len(ru_proxies),
        'eu_count': len(eu_proxies),
        'ru_avg_ping': round(sum(p['response_time'] for p in ru_proxies) / len(ru_proxies), 3) if ru_proxies else 0,
        'eu_avg_ping': round(sum(p['response_time'] for p in eu_proxies) / len(eu_proxies), 3) if eu_proxies else 0,
        'ru_top_domains': dict(Counter(p['domain'] for p in ru_proxies if p['domain'] != 'unknown').most_common(10)),
        'eu_top_domains': dict(Counter(p['domain'] for p in eu_proxies if p['domain'] != 'unknown').most_common(10)),
        'sources_checked': len(SOURCES),
        'execution_time': round(time.time() - start_time, 2)
    }
    
    with open(OUTPUT_STATS, "w", encoding="utf-8") as f:
        json.dump(stats, f, indent=2, ensure_ascii=False)
    logger.info(f"📊 Статистика: {OUTPUT_STATS}")
    
    print()
    print("=" * 60)
    print(f"⏱ Время выполнения: {time.time() - start_time:.2f}с")
    print("✅ Готово!")
    print("=" * 60)

if __name__ == "__main__":
    main()
