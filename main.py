import requests
import re
import socket
import concurrent.futures
import time
from urllib.parse import urlparse, parse_qs
from collections import Counter
import logging

# Настройка логирования
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Расширенные источники
SOURCES = [
    "https://raw.githubusercontent.com/SoliSpirit/mtproto/master/proxies.txt",
    "https://raw.githubusercontent.com/hookzof/socks5_list/master/tg/mtproto.json",
    "https://raw.githubusercontent.com/soroushmirzaei/telegram-proxies-collector/main/proxies.txt",
    "https://raw.githubusercontent.com/MrPotat-00/MTProtoProxiesScraper/main/proxies.txt",
    "https://raw.githubusercontent.com/DigneZzZ/telegram-mtproto-proxies/master/proxy_list.txt"
]

OUTPUT_FILE = "proxy_list.txt"
TIMEOUT = 3  # Увеличен тайм-аут
MAX_WORKERS = 100  # Больше потоков для быстроты

# Список популярных доменов Fake-TLS для качественных прокси
QUALITY_DOMAINS = [
    'microsoft.com', 'google.com', 'cloudflare.com', 
    'azure.com', 'amazon.com', 'bing.com'
]

def parse_proxy(line):
    """Универсальный парсер для всех форматов прокси"""
    # Формат tg://
    tg_pattern = r"tg://proxy\?(.+)"
    match = re.search(tg_pattern, line)
    if match:
        params = parse_qs(match.group(1))
        server = params.get('server', [None])[0]
        port = params.get('port', [None])[0]
        secret = params.get('secret', [None])[0]
        if server and port and secret:
            return server, int(port), secret
    
    # Формат t.me
    tme_pattern = r"t\.me/proxy\?(.+)"
    match = re.search(tme_pattern, line)
    if match:
        params = parse_qs(match.group(1))
        server = params.get('server', [None])[0]
        port = params.get('port', [None])[0]
        secret = params.get('secret', [None])[0]
        if server and port and secret:
            return server, int(port), secret
    
    # Формат JSON-объекта в строке
    json_pattern = r'(?:server|host)["\s:]+([^"&\s]+).*?port["\s:]+(\d+).*?secret["\s:]+([A-Za-z0-9]+)'
    match = re.search(json_pattern, line, re.IGNORECASE)
    if match:
        return match.group(1), int(match.group(2)), match.group(3)
    
    return None

def decode_secret_domain(secret):
    """Извлекает домен из Fake-TLS секрета"""
    if not secret.startswith('ee'):
        return None
    try:
        # ee + hex-encoded domain
        hex_domain = secret[2:]
        # Убираем возможные дополнительные параметры после домена
        hex_domain = hex_domain[:hex_domain.find('00')] if '00' in hex_domain else hex_domain
        domain = bytes.fromhex(hex_domain).decode('utf-8', errors='ignore')
        return domain
    except:
        return None

def is_quality_secret(secret):
    """Расширенная проверка качества секрета"""
    if not secret or len(secret) < 4:
        return False
    
    # Fake-TLS (приоритет)
    if secret.startswith("ee"):
        domain = decode_secret_domain(secret)
        if domain:
            # Проверяем, содержит ли домен качественные имена
            for quality_domain in QUALITY_DOMAINS:
                if quality_domain in domain.lower():
                    return True
        return True  # Все равно принимаем Fake-TLS
    
    # Random padding (менее приоритетно)
    if secret.startswith("dd"):
        return True
    
    return False

def get_secret_score(secret):
    """Оценка качества секрета (чем выше, тем лучше)"""
    score = 0
    
    if secret.startswith("ee"):
        score += 10
        domain = decode_secret_domain(secret)
        if domain:
            for quality_domain in QUALITY_DOMAINS:
                if quality_domain in domain.lower():
                    score += 5
                    break
    elif secret.startswith("dd"):
        score += 5
    
    return score

def check_port_advanced(host, port):
    """Улучшенная проверка порта с дополнительной валидацией"""
    try:
        # Проверка DNS
        socket.gethostbyname(host)
        
        # Проверка подключения
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)
        result = sock.connect_ex((host, port))
        sock.close()
        
        return result == 0
    except:
        return False

def check_response_time(host, port):
    """Измеряет время отклика прокси"""
    try:
        start = time.time()
        with socket.create_connection((host, port), timeout=TIMEOUT):
            return time.time() - start
    except:
        return float('inf')

def process_source(url):
    """Обработка источника с retry логикой"""
    proxies = []
    max_retries = 3
    
    for attempt in range(max_retries):
        try:
            resp = requests.get(url, timeout=15, headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            })
            text = resp.text
            
            # JSON формат
            if url.endswith(".json"):
                try:
                    data = resp.json()
                    if isinstance(data, list):
                        for item in data:
                            host = item.get('host') or item.get('server')
                            port = item.get('port')
                            secret = item.get('secret')
                            if host and port and secret:
                                proxies.append((host, int(port), secret))
                except Exception as e:
                    logger.warning(f"JSON parse error for {url}: {e}")
            
            # Текстовый формат
            for line in text.splitlines():
                p = parse_proxy(line)
                if p:
                    proxies.append(p)
            
            logger.info(f"✓ {url}: найдено {len(proxies)} прокси")
            return proxies
            
        except Exception as e:
            logger.warning(f"Попытка {attempt+1}/{max_retries} для {url} не удалась: {e}")
            time.sleep(2)
    
    return proxies

def validate_proxy(proxy):
    """Полная валидация прокси"""
    host, port, secret = proxy
    
    # 1. Проверка секрета
    if not is_quality_secret(secret):
        return None
    
    # 2. Проверка доступности
    if not check_port_advanced(host, port):
        return None
    
    # 3. Измерение времени отклика
    response_time = check_response_time(host, port)
    
    # 4. Оценка качества
    quality_score = get_secret_score(secret)
    
    link = f"tg://proxy?server={host}&port={port}&secret={secret}"
    
    return {
        'link': link,
        'response_time': response_time,
        'quality_score': quality_score,
        'host': host
    }

def main():
    logger.info("🚀 Начинаю сбор MTProto прокси...")
    
    all_candidates = []
    
    # 1. Параллельный сбор из источников
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(SOURCES)) as executor:
        futures = [executor.submit(process_source, url) for url in SOURCES]
        for future in concurrent.futures.as_completed(futures):
            all_candidates.extend(future.result())
    
    # 2. Удаление дубликатов
    unique_candidates = list(set(all_candidates))
    logger.info(f"📊 Найдено уникальных кандидатов: {len(unique_candidates)}")
    
    # 3. Параллельная валидация
    valid_proxies = []
    logger.info("🔍 Проверка доступности и качества...")
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(validate_proxy, p): p for p in unique_candidates}
        
        completed = 0
        for future in concurrent.futures.as_completed(futures):
            completed += 1
            if completed % 50 == 0:
                logger.info(f"Проверено: {completed}/{len(unique_candidates)}")
            
            result = future.result()
            if result:
                valid_proxies.append(result)
    
    # 4. Сортировка по качеству и скорости
    valid_proxies.sort(key=lambda x: (-x['quality_score'], x['response_time']))
    
    logger.info(f"✅ Валидных прокси: {len(valid_proxies)}")
    
    # 5. Статистика
    if valid_proxies:
        avg_response = sum(p['response_time'] for p in valid_proxies if p['response_time'] != float('inf')) / len(valid_proxies)
        logger.info(f"📈 Средний отклик: {avg_response:.2f}с")
        
        # Топ-10 доменов хостов
        host_counter = Counter(p['host'] for p in valid_proxies)
        logger.info(f"🏆 Топ хостов: {host_counter.most_common(5)}")
    
    # 6. Сохранение
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(p['link'] for p in valid_proxies))
    
    logger.info(f"💾 Результаты сохранены в {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
