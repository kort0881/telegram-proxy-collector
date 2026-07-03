#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# MTProto & SOCKS5 Proxy Collector v3.2 (с регионами US и ASIA)

import requests
import re
import socket
import concurrent.futures
import time
from datetime import datetime, timezone
import json
import os
import argparse
import base64
from typing import Optional, Set, List, Dict, Any, Tuple

# ------------------ НАСТРОЙКИ ------------------
RU_DOMAINS = ['.ru', 'yandex', 'vk.com', 'mail.ru', 'ok.ru', 'dzen', 'rutube', 'sber', 'tinkoff', 'vtb', 'gosuslugi', 'nalog', 'mos.ru', 'ozon', 'wildberries', 'avito', 'kinopoisk', 'mts', 'beeline']
US_DOMAINS = ['.us', '.nyc', '.la', '.sf', '.dallas', 'amazonaws.com', 'digitalocean.com', '.gov', 'cloudflare.com']
ASIA_DOMAINS = ['.asia', '.jp', '.cn', '.sg', '.hk', '.kr', '.in', '.tw', '.ph', '.my', '.id', '.vn', '.th']
BLOCKED = ['instagram', 'facebook', 'twitter', 'bbc', 'meduza', 'linkedin', 'torproject']

# ---------- MTProto источники ----------
SOURCES = [
    "https://raw.githubusercontent.com/SoliSpirit/mtproto/master/all_proxies.txt",
    "https://raw.githubusercontent.com/Grim1313/mtproto-for-telegram/refs/heads/master/all_proxies.txt",
    "https://raw.githubusercontent.com/ALIILAPRO/MTProtoProxy/main/mtproto.txt",
    "https://mtpro.xyz/api/?type=mtproto",
    "https://mtpro.xyz/api/?type=mtproto-ru",
    "https://raw.githubusercontent.com/hookzof/socks5_list/master/tg/mtproto.txt",
    "https://raw.githubusercontent.com/Freedom-Guard/Proxy/main/proxies/mtproto.txt",
    "https://raw.githubusercontent.com/securemanager/MTPROTO/main/proxies.txt",
    "https://raw.githubusercontent.com/kort0881/telegram-proxy-collector/main/mtproto_proxies.txt",
    "https://raw.githubusercontent.com/seriyps/mtproto_proxy/master/proxies.txt",
    "https://raw.githubusercontent.com/MTProto/MTProtoProxy/master/proxies/mtproto.txt",
    "https://raw.githubusercontent.com/mtProtoProxy/MTProxy-official/master/proxies.txt",
    "https://raw.githubusercontent.com/V2RAYCONFIGSPOOL/TELEGRAM_PROXY_SUB/refs/heads/main/telegram_proxy_no1.txt",
    "https://raw.githubusercontent.com/V2RAYCONFIGSPOOL/TELEGRAM_PROXY_SUB/refs/heads/main/telegram_proxy_no2.txt",
    "https://raw.githubusercontent.com/V2RAYCONFIGSPOOL/TELEGRAM_PROXY_SUB/refs/heads/main/telegram_proxy_no3.txt",
    "https://raw.githubusercontent.com/V2RAYCONFIGSPOOL/TELEGRAM_PROXY_SUB/refs/heads/main/telegram_proxy_no4.txt",
    "https://raw.githubusercontent.com/V2RAYCONFIGSPOOL/TELEGRAM_PROXY_SUB/refs/heads/main/telegram_proxy_no5.txt",
    "https://raw.githubusercontent.com/V2RAYCONFIGSPOOL/TELEGRAM_PROXY_SUB/refs/heads/main/telegram_proxy_no6.txt",
    "https://raw.githubusercontent.com/V2RAYCONFIGSPOOL/TELEGRAM_PROXY_SUB/refs/heads/main/telegram_proxy_no7.txt",
    "https://raw.githubusercontent.com/V2RAYCONFIGSPOOL/TELEGRAM_PROXY_SUB/refs/heads/main/telegram_proxy_no8.txt",
    "https://raw.githubusercontent.com/V2RAYCONFIGSPOOL/TELEGRAM_PROXY_SUB/refs/heads/main/telegram_proxy_no9.txt",
    "https://raw.githubusercontent.com/V2RAYCONFIGSPOOL/TELEGRAM_PROXY_SUB/refs/heads/main/telegram_proxy_no10.txt",
    "https://raw.githubusercontent.com/Surfboardv2ray/TGProto/refs/heads/main/proxies.txt",
    "https://raw.githubusercontent.com/iwh3n/tg-proxy/refs/heads/main/proxys/All_Proxys.txt",
    "https://raw.githubusercontent.com/kubiknubika/my-tg-proxies/refs/heads/main/data/proxies.json",
    "https://raw.githubusercontent.com/shablin/mtproto-proxy/refs/heads/main/data/valid_proxy.json",
    "https://raw.githubusercontent.com/MustafaBaqer/VestraNet-Nodes/refs/heads/main/protocols/mtproto.txt",
    "https://raw.githubusercontent.com/helptmoop/Free-Telegram-Proxies/refs/heads/main/global-iran-russia-proxies.txt",
    "https://raw.githubusercontent.com/helptmoop/Free-Telegram-Proxies/refs/heads/main/turkmenistan-global-iran-russia.txt",
    "https://raw.githubusercontent.com/Argh94/Proxy-List/refs/heads/main/MTProto.txt",
    "https://raw.githubusercontent.com/McDaived/ProxyDaiv/refs/heads/main/public/proxies.json",
    "https://raw.githubusercontent.com/klondike0x/mtp4tg-proxies/refs/heads/main/all_proxies.txt",
    "https://raw.githubusercontent.com/weltimistar777-crypto/MTProxy/refs/heads/main/proxy.txt",
    "https://raw.githubusercontent.com/Therealwh/MTPproxyLIST/refs/heads/main/verified/proxy_all_verified.txt",
    "https://raw.githubusercontent.com/Therealwh/MTPproxyLIST/refs/heads/main/verified/proxy_all_tme_verified.txt",
    "https://raw.githubusercontent.com/Airuop/MTProtoCollector/refs/heads/main/proxy/mtproto.json",
    "https://raw.githubusercontent.com/blog1703/tgonline/refs/heads/main/proxies.txt",
]

# ---------- SOCKS5 источники ----------
SOCKS_SOURCES = [
    "https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt",
    "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks5&timeout=5000&country=all",
    "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks5.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS5_RAW.txt",
    "https://raw.githubusercontent.com/fyvri/fresh-proxy-list/archive/storage/classic/socks5.txt",
    "https://gist.githubusercontent.com/December000/fd23d2530ffc29264297a5e687a79ecd/raw/all.yaml",
    "https://raw.githubusercontent.com/CB-X2-Jun/proxy-lists/main/proxy.txt",
    "https://raw.githubusercontent.com/CB-X2-Jun/proxy-lists/main/public/proxies.json",
    "https://raw.githubusercontent.com/ProxyScrape/free-proxy-list/refs/heads/main/proxies/all/data.txt",
]

def _valid_port(p: str) -> bool:
    try:
        return 1 <= int(p) <= 65535
    except ValueError:
        return False

def _is_blocked(secret: str, domain: Optional[str]) -> bool:
    return len(secret) < 16 or (domain and any(b in domain for b in BLOCKED))

def _detect_region(domain: Optional[str]) -> str:
    if not domain:
        return 'eu'
    domain_lower = domain.lower()
    if any(m in domain_lower for m in RU_DOMAINS):
        return 'ru'
    if any(m in domain_lower for m in US_DOMAINS):
        return 'us'
    if any(m in domain_lower for m in ASIA_DOMAINS):
        return 'asia'
    return 'eu'

def decode_domain(secret: str) -> Optional[str]:
    """Декодирует домен из секрета MTProto (формат ee...)."""
    if not secret or not secret.startswith('ee'): 
        return None
    try:
        chars = []
        for i in range(2, len(secret) - 1, 2):
            v = int(secret[i:i+2], 16)
            if v == 0: break
            if 32 <= v <= 126: 
                chars.append(chr(v))
        return ''.join(chars).lower() or None
    except (ValueError, IndexError):
        return None

def get_proxies_from_text(text: str) -> Set[Tuple[str, str, int, Any]]:
    proxies = set()
    mtproto_ips = set()

    # 1. MTProto (tg:// и t.me/)
    for h, p, s in re.findall(r'tg://proxy\?server=([^&\s]+)&port=(\d+)&secret=([A-Za-z0-9_=+/%-]+)', text, re.I):
        if _valid_port(p):
            proxies.add(('mtproto', h, int(p), s))
            mtproto_ips.add((h, int(p)))

    for h, p, s in re.findall(r't\.me/proxy\?server=([^&\s]+)&port=(\d+)&secret=([A-Za-z0-9_=+/%-]+)', text, re.I):
        if _valid_port(p):
            proxies.add(('mtproto', h, int(p), s))
            mtproto_ips.add((h, int(p)))

    # 2. MTProto (IP:PORT:SECRET)
    for h, p, s in re.findall(r'([A-Za-z0-9\.-]+):(\d+):([A-Fa-f0-9]{16,})', text):
        if _valid_port(p):
            proxies.add(('mtproto', h, int(p), s))
            mtproto_ips.add((h, int(p)))

    # 3. SOCKS5 (tg://socks)
    for h, p in re.findall(r'tg://socks\?server=([^&\s]+)&port=(\d+)', text, re.I):
        if _valid_port(p):
            proxies.add(('socks5', h, int(p), (None, None)))

    # 4. SOCKS5 (socks5://user:pass@ip:port)
    for u, pw, h, p in re.findall(r'socks5://(?:([^:@]+):([^@]+)@)?([A-Za-z0-9\.-]+):(\d+)', text, re.I):
        if _valid_port(p):
            proxies.add(('socks5', h, int(p), (u or None, pw or None)))

    # 5. Специальный парсинг для CB-X2-Jun
    for match in re.findall(r'(socks5)://([\d.]+):(\d+):\w+', text, re.I):
        ip, port = match[1], match[2]
        if _valid_port(port):
            proxies.add(('socks5', ip, int(port), (None, None)))

    # 6. Оставшиеся IP:PORT
    for h, p in re.findall(r'(\d+\.\d+\.\d+\.\d+):(\d+)', text):
        if _valid_port(p) and (h, int(p)) not in mtproto_ips:
            proxies.add(('socks5', h, int(p), (None, None)))

    # 7. JSON парсинг
    txt = text.strip()
    if txt.startswith('[') or txt.startswith('{'):
        try:
            data = json.loads(txt)
            items = data if isinstance(data, list) else [data]
            for item in items:
                if not isinstance(item, dict): continue
                if 'host' in item and 'port' in item and 'secret' in item:
                    h, p, s = item['host'], str(item['port']), str(item['secret'])
                    if _valid_port(p):
                        proxies.add(('mtproto', h, int(p), s))
                        mtproto_ips.add((h, int(p)))
                elif 'socks5' in str(item).lower() and ('ip' in item or 'host' in item) and 'port' in item:
                    h = item.get('ip') or item.get('host')
                    p = str(item['port'])
                    if _valid_port(p):
                        proxies.add(('socks5', h, int(p), (None, None)))
        except json.JSONDecodeError:
            pass

    # 8. YAML парсинг
    if 'proxies:' in txt:
        try:
            import yaml
            data = yaml.safe_load(text)
            if isinstance(data, dict) and 'proxies' in data:
                for item in data['proxies']:
                    if item.get('type') == 'socks5':
                        server, port = item.get('server'), str(item.get('port'))
                        if server and port and _valid_port(port):
                            proxies.add(('socks5', server, int(port), (None, None)))
        except ImportError:
            pass
        except Exception:
            pass

    return proxies

def fetch_source(session: requests.Session, url: str, timeout: int = 15) -> str:
    for _ in range(3):
        try:
            r = session.get(url, timeout=timeout)
            if r.status_code == 200: 
                return r.text
        except requests.RequestException:
            pass
        time.sleep(0.5)
    return ''

def check_proxy_tcp(p: Tuple[str, str, int, Any], timeout: float) -> Optional[Dict[str, Any]]:
    typ, host, port, extra = p
    
    if typ == 'mtproto':
        secret = extra
        domain = decode_domain(secret)
        if _is_blocked(secret, domain): 
            return None
        link = f'tg://proxy?server={host}&port={port}&secret={secret}'
        region = _detect_region(domain)
        domain_str = domain or ''
    else:
        link = f'tg://socks?server={host}&port={port}'
        region = 'eu'  # для SOCKS5 регион не определяем, оставляем eu
        domain_str = ''

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            start = time.time()
            s.connect((host, port))
            ping = round(time.time() - start, 3)
            
        return {
            'type': typ, 'host': host, 'port': port,
            'secret': extra if typ == 'mtproto' else None,
            'link': link, 'ping': ping, 'region': region,
            'domain': domain_str, 'method': 'TCP_OK', 'probe_resistant': False
        }
    except (socket.timeout, socket.error, OSError):
        return None

def deduplicate_and_sort(proxies: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen = set()
    unique = []
    for p in proxies:
        key = (p['type'], p['host'], p['port'], p.get('secret'))
        if key not in seen:
            seen.add(key)
            unique.append(p)
            
    unique.sort(key=lambda x: (
        0 if (x['type'] == 'mtproto' and x.get('probe_resistant', False)) else 1 if x['type'] == 'mtproto' else 2, 
        x['ping']
    ))
    return unique

def load_local_proxies(file_path: str) -> Set[Tuple[str, str, int, Any]]:
    if not os.path.isfile(file_path): 
        return set()
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            proxies = get_proxies_from_text(f.read())
        print(f"✓ Загружено {len(proxies)} прокси из {file_path}")
        return proxies
    except IOError as e: 
        print(f"✗ Ошибка чтения {file_path}: {e}")
        return set()

def run(args):
    start_time = time.time()
    print('🚀 MTProxy Collector v3.2 (с регионами US и ASIA)')
    print('=' * 48)
    
    os.makedirs(args.output_dir, exist_ok=True)

    session = requests.Session()
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
    })

    all_raw = set()

    print('\n📥 Сбор MTProto...')
    for url in SOURCES:
        name = (url.split('/')[-1] or url.split('/')[-2])[:42]
        text = fetch_source(session, url)
        if text:
            ext = get_proxies_from_text(text)
            cnt = sum(1 for x in ext if x[0] == 'mtproto')
            all_raw.update(ext)
            print(f'  ✓ {name:<42} +{cnt} MTProto')
        else: 
            print(f'  ✗ {name:<42} недоступен')

    print('\n📥 Сбор SOCKS5...')
    for url in SOCKS_SOURCES:
        name = (url.split('/')[-1] or url.split('/')[-2])[:42]
        text = fetch_source(session, url)
        if text:
            ext = get_proxies_from_text(text)
            cnt = sum(1 for x in ext if x[0] == 'socks5')
            all_raw.update(ext)
            print(f'  ✓ {name:<42} +{cnt} SOCKS5')
        else: 
            print(f'  ✗ {name:<42} недоступен')

    if args.manual:
        all_raw.update(load_local_proxies(args.manual))

    print(f'\n🧩 Уникальных прокси всего: {len(all_raw)}')
    if not all_raw:
        print('\n⚠️ Нет прокси. Завершение.')
        return

    print(f'\n⚡ Проверка {len(all_raw)} прокси (TCP ping)...\n')
    valid = []
    checked = 0
    total = len(all_raw)
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as ex:
        futures = {ex.submit(check_proxy_tcp, p, args.timeout): p for p in all_raw}
        for f in concurrent.futures.as_completed(futures):
            res = f.result()
            checked += 1
            if res: 
                valid.append(res)
            if checked % 100 == 0 or checked == total:
                print(f'  [{checked}/{total}] {checked/total*100:.0f}% | найдено: {len(valid)}')

    if not valid:
        print('\n⚠️ Рабочих прокси не найдено.')
        return

    valid = deduplicate_and_sort(valid)
    mtproto_ru = [x for x in valid if x['type'] == 'mtproto' and x['region'] == 'ru']
    mtproto_eu = [x for x in valid if x['type'] == 'mtproto' and x['region'] == 'eu']
    mtproto_us = [x for x in valid if x['type'] == 'mtproto' and x['region'] == 'us']
    mtproto_asia = [x for x in valid if x['type'] == 'mtproto' and x['region'] == 'asia']
    socks5 = [x for x in valid if x['type'] == 'socks5']
    
    top = args.top if args.top > 0 else len(valid)
    utc = datetime.now(timezone.utc)

    print(f'\n💾 Сохранение в {args.output_dir}/...')
    
    files_data = {
        'proxy_ru_verified.txt': (mtproto_ru[:top], f'# MTProto RU ({len(mtproto_ru[:top])})\n# Updated: {utc}\n\n', lambda x: x['link']),
        'proxy_eu_verified.txt': (mtproto_eu[:top], f'# MTProto EU ({len(mtproto_eu[:top])})\n# Updated: {utc}\n\n', lambda x: x['link']),
        'proxy_us_verified.txt': (mtproto_us[:top], f'# MTProto US ({len(mtproto_us[:top])})\n# Updated: {utc}\n\n', lambda x: x['link']),
        'proxy_asia_verified.txt': (mtproto_asia[:top], f'# MTProto ASIA ({len(mtproto_asia[:top])})\n# Updated: {utc}\n\n', lambda x: x['link']),
        'socks5_proxies.txt': (socks5[:top], f'# SOCKS5 ({len(socks5[:top])})\n# Updated: {utc}\n\n', lambda x: f'tg://socks?server={x["host"]}&port={x["port"]}'),
    }
    
    for filename, (data, header, formatter) in files_data.items():
        with open(f'{args.output_dir}/{filename}', 'w', encoding='utf-8') as f:
            f.write(header + '\n'.join(formatter(x) for x in data))

    with open(f'{args.output_dir}/proxy_all_verified.json', 'w', encoding='utf-8') as f:
        json.dump(valid[:top], f, indent=2, ensure_ascii=False)

    elapsed = round(time.time() - start_time, 1)
    print('=' * 48)
    print(f'✅ MTProto RU: {len(mtproto_ru)}  EU: {len(mtproto_eu)}  US: {len(mtproto_us)}  ASIA: {len(mtproto_asia)}  SOCKS5: {len(socks5)}')
    if mtproto_ru: print(f'🏆 Лучший RU: {mtproto_ru[0]["host"]}:{mtproto_ru[0]["port"]} ({mtproto_ru[0]["ping"]}s)')
    if mtproto_eu: print(f'🏆 Лучший EU: {mtproto_eu[0]["host"]}:{mtproto_eu[0]["port"]} ({mtproto_eu[0]["ping"]}s)')
    if mtproto_us: print(f'🏆 Лучший US: {mtproto_us[0]["host"]}:{mtproto_us[0]["port"]} ({mtproto_us[0]["ping"]}s)')
    if mtproto_asia: print(f'🏆 Лучший ASIA: {mtproto_asia[0]["host"]}:{mtproto_asia[0]["port"]} ({mtproto_asia[0]["ping"]}s)')
    if socks5: print(f'🏆 Лучший SOCKS5: {socks5[0]["host"]}:{socks5[0]["port"]} ({socks5[0]["ping"]}s)')
    print(f'⏱️ Время: {elapsed}s')
    print('=' * 48)

def main():
    parser = argparse.ArgumentParser(description="MTProto & SOCKS5 Proxy Collector")
    parser.add_argument('--timeout', type=float, default=2.0, help="TCP timeout в секундах")
    parser.add_argument('--workers', type=int, default=100, help="Количество потоков для проверки")
    parser.add_argument('--top', type=int, default=0, help="Сохранить только топ X прокси (0 = все)")
    parser.add_argument('--output-dir', default='verified', help="Папка для сохранения результатов")
    parser.add_argument('--manual', type=str, help="Путь к локальному файлу с прокси для добавления")
    args = parser.parse_args()
    
    run(args)

if __name__ == '__main__':
    main()
