import requests
import re
import socket
import concurrent.futures

# Источники (Raw ссылки на списки, которые уже обновляются авторами)
SOURCES = [
    "https://raw.githubusercontent.com/SoliSpirit/mtproto/master/proxies.txt",
    "https://raw.githubusercontent.com/hookzof/socks5_list/master/tg/mtproto.json",
    "https://raw.githubusercontent.com/soroushmirzaei/telegram-proxies-collector/main/proxies.txt"
]

OUTPUT_FILE = "proxy_list.txt"
TIMEOUT = 2  # Тайм-аут проверки порта (сек)

def parse_proxy(line):
    """Вытаскивает server, port, secret из строки"""
    # Паттерн для ссылок tg:// и t.me
    pattern = r"(?:server|server_name)=([^&]+)&(?:port|port_number)=(\d+)&secret=([A-Za-z0-9]+)"
    match = re.search(pattern, line)
    if match:
        return match.group(1), int(match.group(2)), match.group(3)
    return None

def is_quality_secret(secret):
    """Фильтр для РФ: только Fake-TLS (ee) или Random (dd)"""
    return secret.startswith("ee") or secret.startswith("dd")

def check_port(host, port):
    """Быстрая проверка доступности порта (без проверки протокола)"""
    try:
        with socket.create_connection((host, port), timeout=TIMEOUT):
            return True
    except (socket.timeout, socket.error):
        return False

def process_source(url):
    proxies = []
    try:
        resp = requests.get(url, timeout=10)
        text = resp.text
        
        # Если это JSON (hookzof)
        if url.endswith(".json"):
            try:
                data = resp.json()
                for item in data:
                    proxies.append((item.get('host'), int(item.get('port')), item.get('secret')))
            except: pass
        # Если это обычный текст
        else:
            for line in text.splitlines():
                p = parse_proxy(line)
                if p: proxies.append(p)
    except Exception as e:
        print(f"Ошибка загрузки {url}: {e}")
    return proxies

def main():
    print("🚀 Начинаю сбор прокси...")
    
    all_candidates = []
    
    # 1. Сбор
    for url in SOURCES:
        data = process_source(url)
        all_candidates.extend(data)
    
    # Удаляем дубликаты
    unique_candidates = list(set(all_candidates))
    print(f"Найдено кандидатов: {len(unique_candidates)}")
    
    valid_proxies = []
    
    # 2. Фильтрация и проверка
    print("🔍 Начинаю проверку доступности...")
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        future_to_proxy = {
            executor.submit(check_port, p[0], p[1]): p for p in unique_candidates 
            if is_quality_secret(p[2]) # Сначала фильтруем секрет
        }
        
        for future in concurrent.futures.as_completed(future_to_proxy):
            is_open = future.result()
            proxy = future_to_proxy[future]
            
            if is_open:
                link = f"tg://proxy?server={proxy[0]}&port={proxy[1]}&secret={proxy[2]}"
                valid_proxies.append(link)

    print(f"✅ Итого валидных прокси: {len(valid_proxies)}")

    # 3. Сохранение
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(valid_proxies))

if __name__ == "__main__":
    main()
