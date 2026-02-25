import requests
import re
import socket
import concurrent.futures
import time
from datetime import datetime
import json
import os

# ИСТОЧНИКИ (основные txt-списки MTProto)
SOURCES = [
    # SoliSpirit – исходный all_proxies.txt (автоапдейт каждые 12ч)
    "https://raw.githubusercontent.com/SoliSpirit/mtproto/master/all_proxies.txt",  # [web:32]

    # Grim1313 – форк, синхронизируется с SoliSpirit
    "https://raw.githubusercontent.com/Grim1313/mtproto-for-telegram/refs/heads/master/all_proxies.txt",  # [web:20]

    # Доп. источник от ALIILAPRO
    "https://raw.githubusercontent.com/ALIILAPRO/MTProtoProxy/main/mtproto.txt",  # [web:35]

    # Старый, но полезный список
    "https://raw.githubusercontent.com/yemixzy/proxy-projects/main/proxies/mtproto.txt",
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

    # tg://proxy?server=...&port=...&secret=...
    tg_pattern = re.compile(
        r'tg://proxy\?server=([^&\s]+)&port=(\d+)&secret=([A-Za-z0-9_=-]+)',
        re.IGNORECASE
    )
    for h, p, s in tg_pattern.findall(text):
        proxies.add((h, int(p), s))

    # t.me/proxy?server=...&port=...&secret=...
    tme_pattern = re.compile(
        r't\.me/proxy\?server=([^&\s]+)&port=(\d+)&secret=([A-Za-z0-9_=-]+)',
        re.IGNORECASE
    )
    for h, p, s in tme_pattern.findall(text):
        proxies.add((h, int(p), s))

    # host:port:secret
    simple_pattern = re.compile(
        r'([a-zA-Z0-9\.-]+):(\d+):([A-Fa-f0-9]{16,})'
    )
    for h, p, s in simple_pattern.findall(text):
        proxies.add((h, int(p), s))

    # Попытка парсить JSON
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
        'host': host,
        'port': port,
        'secret': secret,
        'link': f"tg://proxy?server={host}&port={port}&secret={secret}",
        'ping': ping,
        'region': region
    }


def make_tme_link(host, port, secret):
    # Ссылка, которая открывается через браузер: t.me/proxy...
    return f"https://t.me/proxy?server={host}&port={port}&secret={secret}"


def main():
    start_time = time.time()
    print("🚀 Start collecting...")
    all_raw = set()

    # 1. Загрузка из источников
    for url in SOURCES:
        name = url.split('/')[3]
        try:
            r = requests.get(url, timeout=15)
            if r.status_code != 200:
                print(f"✗ {name} -> HTTP {r.status_code}")
                continue
            extracted = get_proxies_from_text(r.text)
            all_raw.update(extracted)
            print(f"✓ {name} -> {len(extracted)}")
        except Exception as e:
            print(f"✗ Failed: {name} ({e})")

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

    # 2. Сохранение tg:// ссылок
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

    # 3. Дополнительно: t.me/proxy формат (удобно кликать из браузера)
    with open('proxy_all_tme.txt', 'w', encoding='utf-8') as f:
        f.write(f"# All Proxies (t.me format, {len(valid)})\n")
        f.write(f"# Updated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}\n\n")
        for x in valid:
            f.write(make_tme_link(x['host'], x['port'], x['secret']) + "\n")

    # 4. Статистика
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


if __name__ == "__main__":
    main()

