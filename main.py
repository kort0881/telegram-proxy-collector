import requests
import re
import socket
import concurrent.futures
import time
from datetime import datetime
import json
import os

# ИСТОЧНИКИ (обновлённые)
SOURCES = [
    # SoliSpirit – автоапдейт каждые 12 часов
    "https://raw.githubusercontent.com/SoliSpirit/mtproto/master/all_proxies.txt",  # [web:32]

    # ALIILAPRO – свежие mtproto-прокси
    "https://raw.githubusercontent.com/ALIILAPRO/MTProtoProxy/main/mtproto.txt",    # [web:35]

    # Grim1313 – список mtproto
    "https://raw.githubusercontent.com/Grim1313/mtproto-for-telegram/main/proxies.txt",  # [web:20]

    # Старые, но ещё живые источники
    "https://raw.githubusercontent.com/yemixzy/proxy-projects/main/proxies/mtproto.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/MTPROTO_RAW.txt",
]

# Ручные прокси, которые ты прислал (будут добавляться к собранным)
MANUAL_PROXIES = [
    ("Online.harcibasheokeye.ir", 987, "7gAA8A8Pd1VV____9QBuLmltZWRpYS5zdGVhbXBvd2VyZWQuY29t"),
    ("193.124.49.92", 443, "a4b93f8c7e5d21fa0c6e4b2d8f19c73a"),
    ("14.102.10.145", 8443, "eeNEgYdJvXrFGRMCIMJdCQ"),
    ("195.254.165.96", 65535, "10446282fff6fffffff80000fff80000"),
    ("films.video-fun-new.com.de", 443, "eefeb6d369848a45bd91fd87e332faa3d063727970747061642e6672"),
    ("77.72.80.86", 443, "eeNEgYdJvXrFGRMCIMJdCQ"),
    ("185.84.157.21", 444, "FgMBAgABAAH8AxOG4kw63Q=="),
    ("garden-paradise.karako.co.uk", 443, "ee1603010200010001fc030386e24c3add626973636F7474692E79656B74616E65742E636F6D"),
    ("paitakht.arasto.info", 443, "7hYDAQIAAQAB_AMDhuJMOt1iaXNjb3R0aS55ZWt0YW5ldC5jb20"),
    ("95.217.169.14", 443, "eeNEgYdJvXrFGRMCIMJdCQtY2RueWVrdGFuZXQuY29tZmFyYWthdi5jb212YW4ubmFqdmEuY29tAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
    ("62.60.176.36", 443, "7hYDAQIAAQAH8AMDhuJMOt1tZWRpYS5zdGVhbXBvd2VyZWQuY29tbWVkaWEuc3RlYW1wb3dlcmVkLmNvbQ"),
    ("10.full.filmne1t.info", 8080, "dd49a70de57a60174f18dfd7fe6ef6aaf5"),
    ("78.46.234.177", 443, "DDBighLLvXrFGRMCBVJdFQ=="),
    ("65.109.244.118", 8080, "ProxyQavi____ProxymelgACM4eFlnUldQOFpvTHVwZmNpaVI2ZkJFNDJMSXJxUW1yT2s4YzRCaVRaLi11cGRhdAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
    ("03363673733776377.meli.zban-mas.info", 8888, "7gAA8A8Pd1VV____9QBuLmltZWRpYS5zdGVhbXBvd2VyZWQuY29t"),
    ("Shooka-Koopa.xhivar-nokian.rang-mavar-zhos.info", 2040, "EEABAzJJlbB8AwOG6Ibn8Q"),
    ("morgh.2p2p.ir", 8080, "7maIHm4ebR_2ZmZmYW1mrq5ob3N0aXJhbi5jbG91ZA=="),
    ("212.34.151.112", 443, "eeNEgYdJvXrFGRMCIMJdCQ"),
    ("udp.road-digger.info.", 61016, "7nnnAQIAAQAH8AMDhuJMOt0"),
    ("87.28.51.0.mamadjoon.ir", 231, "ee5lrPbFdb1vizwd3HEHow"),
]

TIMEOUT = 2.0
MAX_WORKERS = 150

RU_DOMAINS = [
    '.ru', 'yandex', 'vk.com', 'mail.ru', 'ok.ru', 'dzen', 'rutube',
    'sber', 'tinkoff', 'vtb', 'gosuslugi', 'nalog', 'mos.ru',
    'ozon', 'wildberries', 'avito', 'kinopoisk', 'mts', 'beeline'
]

BLOCKED = ['instagram', 'facebook', 'twitter', 'bbc', 'meduza', 'linkedin', 'torproject']


def get_proxies_from_text(text: str):
    proxies = set()

    # 1) Пробуем достать tg://proxy?server=...&port=...&secret=...
    tg_pattern = re.compile(
        r'tg://proxy\?server=([^&\s]+)&port=(\d+)&secret=([A-Za-z0-9_=-]+)',
        re.IGNORECASE
    )
    for h, p, s in tg_pattern.findall(text):
        proxies.add((h, int(p), s))

    # 2) Пробуем формат t.me/proxy?server=...
    tme_pattern = re.compile(
        r't.me/proxy\?server=([^&\s]+)&port=(\d+)&secret=([A-Za-z0-9_=-]+)',
        re.IGNORECASE
    )
    for h, p, s in tme_pattern.findall(text):
        proxies.add((h, int(p), s))

    # 3) Старый формат host:port:secret
    simple_pattern = re.compile(
        r'([a-zA-Z0-9\.-]+):(\d+):([A-Fa-f0-9]{16,})'
    )
    for h, p, s in simple_pattern.findall(text):
        proxies.add((h, int(p), s))

    # 4) Попытка парсить JSON-списки
    txt = text.strip()
    if txt.startswith('[') or txt.startswith('{'):
        try:
            data = json.loads(txt)
            if isinstance(data, list):
                for item in data:
                    if isinstance(item, dict):
                        host = item.get('host') or item.get('server')
                        port = item.get('port')
                        secret = item.get('secret')
                        if host and port and secret:
                            proxies.add((host, int(port), str(secret)))
        except Exception:
            pass

    return proxies


def decode_domain(secret: str):
    if not secret.startswith('ee'):
        return None
    try:
        chars = []
        for i in range(2, len(secret), 2):
            val = int(secret[i:i + 2], 16)
            if val == 0:
                break
            chars.append(chr(val))
        return "".join(chars).lower()
    except Exception:
        return None


def check_proxy(p):
    host, port, secret = p
    domain = decode_domain(secret)

    if len(secret) < 16:
        return None
    if domain:
        for b in BLOCKED:
            if b in domain:
                return None

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(TIMEOUT)
        start = time.time()
        s.connect((host, port))
        ping = time.time() - start
        s.close()
    except Exception:
        return None

    region = 'eu'
    if domain:
        for r in RU_DOMAINS:
            if r in domain:
                region = 'ru'
                break

    return {
        'link': f"tg://proxy?server={host}&port={port}&secret={secret}",
        'ping': ping,
        'region': region
    }


def main():
    start_time = time.time()
    print("🚀 Start collecting...")
    all_raw = set()

    # 1. Грузим из внешних источников
    for url in SOURCES:
        name = url.split('/')[3]
        try:
            r = requests.get(url, timeout=10)
            if r.status_code != 200:
                print(f"✗ {name} -> HTTP {r.status_code}")
                continue
            extracted = get_proxies_from_text(r.text)
            all_raw.update(extracted)
            print(f"✓ {name} -> {len(extracted)}")
        except Exception as e:
            print(f"✗ Failed: {name} ({e})")

    # 2. Добавляем ручные прокси из списка
    before_manual = len(all_raw)
    for h, p, s in MANUAL_PROXIES:
        all_raw.add((h, int(p), s))
    added_manual = len(all_raw) - before_manual
    print(f"✓ Manual list -> {added_manual}")

    print(f"\n⚡ Checking {len(all_raw)} proxies...")
    valid = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as exc:
        futures = {exc.submit(check_proxy, p): p for p in all_raw}
        for f in concurrent.futures.as_completed(futures):
            res = f.result()
            if res:
                valid.append(res)

    ru = sorted([x for x in valid if x['region'] == 'ru'], key=lambda x: x['ping'])
    eu = sorted([x for x in valid if x['region'] == 'eu'], key=lambda x: x['ping'])

    # Сохраняем прокси
    with open('proxy_ru.txt', 'w', encoding='utf-8') as f:
        f.write(f"# RU Proxies ({len(ru)})\n")
        f.write(f"# Updated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}\n\n")
        f.write('\n'.join([x['link'] for x in ru]))

    with open('proxy_eu.txt', 'w', encoding='utf-8') as f:
        f.write(f"# EU Proxies ({len(eu)})\n")
        f.write(f"# Updated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}\n\n")
        f.write('\n'.join([x['link'] for x in eu]))

    with open('proxy_all.txt', 'w', encoding='utf-8') as f:
        f.write(f"# All Proxies ({len(valid)})\n")
        f.write(f"# Updated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}\n\n")
        f.write('\n'.join([x['link'] for x in valid]))

    stats = {
        'updated': datetime.utcnow().isoformat(),
        'total': len(valid),
        'ru_count': len(ru),
        'eu_count': len(eu),
        'sources_checked': len(SOURCES),
        'proxies_checked': len(all_raw),
        'execution_time': round(time.time() - start_time, 2),
        'best_ru_ping': round(ru[0]['ping'], 3) if ru else None,
        'best_eu_ping': round(eu[0]['ping'], 3) if eu else None
    }

    with open('proxy_stats.json', 'w', encoding='utf-8') as f:
        json.dump(stats, f, indent=2, ensure_ascii=False)

    if os.path.exists("proxy_list.txt"):
        os.remove("proxy_list.txt")

    print(f"\n✅ DONE: RU={len(ru)}, EU={len(eu)}, TOTAL={len(valid)}")
    print(f"⏱ Time: {stats['execution_time']}s")


if __name__ == "__main__":
    main()

