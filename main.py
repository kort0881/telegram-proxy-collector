#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# MTProto & SOCKS5 Proxy Collector v3.7
# - Фикс GeoIP: maxminddb.open_database + fallback на geoip2
# - Фильтр подозрительных портов (SSH, MySQL, Postgres и т.д.)
# - TTL для seen-кэша (не более 48 часов)
# - FIX: seen-кэш теперь учитывает secret (разные MTProto на одном IP:port)

import requests
import re
import socket
import concurrent.futures
import time
import random
from datetime import datetime, timezone, timedelta
import json
import os
import argparse
from typing import Optional, Set, List, Dict, Any, Tuple

# ---------- GEOIP (с fallback) ----------
geoip_reader = None
GEOIP_MODE = None   # 'maxminddb' | 'geoip2' | None

try:
    import maxminddb
    _HAS_MAXMIND = hasattr(maxminddb, 'open_database')
except ImportError:
    maxminddb = None
    _HAS_MAXMIND = False

try:
    from geoip2.database import Reader as GeoIP2Reader
    _HAS_GEOIP2 = True
except ImportError:
    GeoIP2Reader = None
    _HAS_GEOIP2 = False

# ------------------ НАСТРОЙКИ ------------------
RU_DOMAINS = ['.ru', 'yandex', 'vk.com', 'mail.ru', 'ok.ru', 'dzen', 'rutube', 'sber', 'tinkoff', 'vtb', 'gosuslugi', 'nalog', 'mos.ru', 'ozon', 'wildberries', 'avito', 'kinopoisk', 'mts', 'beeline']
US_DOMAINS = ['.us', '.nyc', '.la', '.sf', '.dallas', 'amazonaws.com', 'digitalocean.com', '.gov', 'cloudflare.com']
ASIA_DOMAINS = ['.asia', '.jp', '.cn', '.sg', '.hk', '.kr', '.in', '.tw', '.ph', '.my', '.id', '.vn', '.th']
BLOCKED = ['instagram', 'facebook', 'twitter', 'bbc', 'meduza', 'linkedin', 'torproject']

SUSPICIOUS_PORTS = {
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161, 162,
    389, 445, 465, 514, 587, 631, 993, 995, 1080, 1433, 1521,
    2049, 3306, 3389, 5432, 5900, 6379, 9200, 11211, 27017
}

ALLOWED_COUNTRIES = {
    'RU','BY','KZ','UA','MD','AM','GE','AZ','UZ','KG','TJ','TM',
    'DE','NL','FI','GB','FR','SE','PL','CZ','AT','CH','IT','ES',
    'NO','DK','BE','IE','LU','EE','LV','LT','PT','GR','RO','BG',
    'HU','SK','SI','HR','RS','TR','CA','US'
}

# ---------- Источники ----------
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
    "https://moonlunavpn.com/proxies.txt",
    "https://moonlunavpn.com/proxies.json",
    "https://tgmtproxy.github.io/mtproxy/proxies.txt",
    "https://tgmtproxy.github.io/mtproxy/proxies.json",
]

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

# ---------- ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ----------
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
    d = domain.lower()
    if any(m in d for m in RU_DOMAINS):   return 'ru'
    if any(m in d for m in US_DOMAINS):   return 'us'
    if any(m in d for m in ASIA_DOMAINS): return 'asia'
    return 'eu'

def decode_domain(secret: str) -> Optional[str]:
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

def _load_geoip(path: str):
    global GEOIP_MODE
    if _HAS_MAXMIND:
        try:
            reader = maxminddb.open_database(path)
            GEOIP_MODE = 'maxminddb'
            return reader
        except Exception as e:
            print(f'⚠️ maxminddb.open_database не сработал: {e}')
    if _HAS_GEOIP2:
        try:
            reader = GeoIP2Reader(path)
            GEOIP_MODE = 'geoip2'
            return reader
        except Exception as e:
            print(f'⚠️ geoip2.Reader не сработал: {e}')
    return None

def _geo_country(host: str) -> Optional[str]:
    if geoip_reader is None:
        return None
    try:
        info = geoip_reader.get(host)
        if not info:
            return None
        if GEOIP_MODE == 'maxminddb':
            return (info.get('country') or {}).get('iso_code')
        if GEOIP_MODE == 'geoip2':
            return info.country.iso_code if info.country else None
    except Exception:
        return None
    return None

def get_proxies_from_text(text: str) -> Set[Tuple[str, str, int, Any]]:
    proxies = set()
    mtproto_ips = set()

    for h, p, s in re.findall(r'tg://proxy\?server=([^&\s]+)&port=(\d+)&secret=([A-Za-z0-9_=+/%-]+)', text, re.I):
        if _valid_port(p):
            proxies.add(('mtproto', h, int(p), s)); mtproto_ips.add((h, int(p)))
    for h, p, s in re.findall(r't\.me/proxy\?server=([^&\s]+)&port=(\d+)&secret=([A-Za-z0-9_=+/%-]+)', text, re.I):
        if _valid_port(p):
            proxies.add(('mtproto', h, int(p), s)); mtproto_ips.add((h, int(p)))
    for h, p, s in re.findall(r'([A-Za-z0-9\.-]+):(\d+):([A-Fa-f0-9]{16,})', text):
        if _valid_port(p):
            proxies.add(('mtproto', h, int(p), s)); mtproto_ips.add((h, int(p)))
    for h, p in re.findall(r'tg://socks\?server=([^&\s]+)&port=(\d+)', text, re.I):
        if _valid_port(p):
            proxies.add(('socks5', h, int(p), (None, None)))
    for u, pw, h, p in re.findall(r'socks5://(?:([^:@]+):([^@]+)@)?([A-Za-z0-9\.-]+):(\d+)', text, re.I):
        if _valid_port(p):
            proxies.add(('socks5', h, int(p), (u or None, pw or None)))
    for match in re.findall(r'(socks5)://([\d.]+):(\d+):\w+', text, re.I):
        ip, port = match[1], match[2]
        if _valid_port(port):
            proxies.add(('socks5', ip, int(port), (None, None)))

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
                        proxies.add(('mtproto', h, int(p), s)); mtproto_ips.add((h, int(p)))
                elif 'socks5' in str(item).lower() and ('ip' in item or 'host' in item) and 'port' in item:
                    h = item.get('ip') or item.get('host')
                    if h is None: continue
                    p = str(item['port'])
                    if _valid_port(p):
                        proxies.add(('socks5', h, int(p), (None, None)))
        except json.JSONDecodeError:
            pass

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
        except (ImportError, Exception):
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
    host = str(host).strip()
    if not host:
        return None

    if typ == 'mtproto' and port in SUSPICIOUS_PORTS:
        return None

    if geoip_reader is not None:
        country = _geo_country(host)
        if country and country.upper() not in ALLOWED_COUNTRIES:
            return None

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
        region = 'eu'
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
    except (socket.timeout, socket.error, OSError, TypeError):
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

# ---------- SEEN-КЭШ (с secret и TTL) ----------
def _cache_key(p) -> Tuple:
    """Ключ кэша: (type, host, port, secret-or-credentials).
    Разные secret на одном IP:port считаются разными прокси."""
    if len(p) >= 4:
        extra = p[3]
        if isinstance(extra, str):
            return (p[0], p[1], p[2], extra)
        if isinstance(extra, tuple):
            # socks5 с логином/паролем
            return (p[0], p[1], p[2], f"{extra[0] or ''}:{extra[1] or ''}")
    return (p[0], p[1], p[2], '')

def load_seen(path: str, ttl_hours: int = 48) -> Set[Tuple]:
    """Возвращает множество ключей, проверенных за последние ttl_hours.
    Ключи из старого 3-элементного формата игнорируются (автосброс)."""
    if not path or not os.path.isfile(path):
        return set()
    try:
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except Exception as e:
        print(f'⚠️ Не удалось прочитать seen-кэш: {e}')
        return set()

    seen_set = set()
    now = datetime.now(timezone.utc)

    for item in data.get('seen', []):
        if isinstance(item, dict) and 'k' in item and 'ts' in item:
            try:
                ts = datetime.fromisoformat(item['ts'].replace('Z', '+00:00'))
                # берём только 4-элементные ключи (новый формат)
                if now - ts <= timedelta(hours=ttl_hours) and len(item['k']) >= 4:
                    seen_set.add(tuple(item['k']))
            except Exception:
                pass
    return seen_set

def save_seen(path: str, seen):
    if not path:
        return
    try:
        os.makedirs(os.path.dirname(path) or '.', exist_ok=True)
        keys = list(seen)[-100000:]
        now = datetime.now(timezone.utc).isoformat()
        payload = {'seen': [{'k': list(k), 'ts': now} for k in keys]}
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(payload, f)
        print(f'💾 Seen-кэш сохранён: {len(keys)} записей (TTL 48ч)')
    except Exception as e:
        print(f'⚠️ Не удалось сохранить seen-кэш: {e}')

# ---------- MAIN ----------
def run(args):
    global geoip_reader

    start_time = time.time()
    print('🚀 MTProxy Collector v3.7')
    print('=' * 48)

    if args.geoip and os.path.exists(args.geoip):
        geoip_reader = _load_geoip(args.geoip)
        if geoip_reader is not None:
            print(f"✅ geoip.dat загружен ({GEOIP_MODE}) из {args.geoip}")
        else:
            print("⚠️ Не удалось загрузить geoip.dat, проверка по стране отключена")
    else:
        print("⚠️ geoip.dat не указан или не найден, проверка по стране отключена.")

    os.makedirs(args.output_dir, exist_ok=True)

    session = requests.Session()
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
    })

    all_raw: Set[Tuple[str, str, int, Any]] = set()

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

    seen = load_seen(args.seen_file, ttl_hours=args.seen_ttl)
    if seen:
        print(f'📦 Загружено {len(seen)} ранее проверенных прокси из кэша (TTL {args.seen_ttl}ч)')

    fresh_raw = {p for p in all_raw if _cache_key(p) not in seen}
    skipped = len(all_raw) - len(fresh_raw)
    if skipped:
        print(f'♻️ Пропущено (уже проверялись): {skipped}')
    all_raw = fresh_raw

    if args.max_check and len(all_raw) > args.max_check:
        all_raw = set(random.sample(list(all_raw), args.max_check))
        print(f'⚠️ Ограничено до {args.max_check} случайных прокси')

    if not all_raw:
        print('\n⚠️ Нечего проверять после фильтрации. Завершение.')
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
            if checked % 500 == 0 or checked == total:
                print(f'  [{checked}/{total}] {checked/total*100:.0f}% | найдено: {len(valid)}')

    updated_seen = seen | {_cache_key(p) for p in all_raw}
    save_seen(args.seen_file, updated_seen)

    if not valid:
        print('\n⚠️ Рабочих прокси не найдено.')
        return

    valid = deduplicate_and_sort(valid)
    mtproto_ru   = [x for x in valid if x['type'] == 'mtproto' and x['region'] == 'ru']
    mtproto_eu   = [x for x in valid if x['type'] == 'mtproto' and x['region'] == 'eu']
    mtproto_us   = [x for x in valid if x['type'] == 'mtproto' and x['region'] == 'us']
    mtproto_asia = [x for x in valid if x['type'] == 'mtproto' and x['region'] == 'asia']
    socks5       = [x for x in valid if x['type'] == 'socks5']

    top = args.top if args.top > 0 else len(valid)
    utc = datetime.now(timezone.utc)

    print(f'\n💾 Сохранение в {args.output_dir}/...')

    all_proxies = mtproto_ru[:top] + mtproto_eu[:top] + mtproto_us[:top] + mtproto_asia[:top] + socks5[:top]
    all_proxies.sort(key=lambda x: (x['region'], x['ping']))

    link_formatter = lambda x: x['link']

    files_data = {
        'proxy_ru_verified.txt':   (mtproto_ru[:top],   f'# MTProto RU ({len(mtproto_ru[:top])})\n# Updated: {utc}\n\n',   link_formatter),
        'proxy_eu_verified.txt':   (mtproto_eu[:top],   f'# MTProto EU ({len(mtproto_eu[:top])})\n# Updated: {utc}\n\n',   link_formatter),
        'proxy_us_verified.txt':   (mtproto_us[:top],   f'# MTProto US ({len(mtproto_us[:top])})\n# Updated: {utc}\n\n',   link_formatter),
        'proxy_asia_verified.txt': (mtproto_asia[:top], f'# MTProto ASIA ({len(mtproto_asia[:top])})\n# Updated: {utc}\n\n', link_formatter),
        'socks5_proxies.txt':      (socks5[:top],       f'# SOCKS5 ({len(socks5[:top])})\n# Updated: {utc}\n\n',          link_formatter),
        'proxy_all_tme_verified.txt': (all_proxies, f'# Verified Proxies t.me format ({len(all_proxies)})\n# Updated: {utc}\n\n', link_formatter),
        'proxy_all.txt':           (all_proxies, f'# All proxies ({len(all_proxies)})\n# Updated: {utc}\n\n',           link_formatter),
        'proxy_all_verified.txt':  (all_proxies, f'# All verified proxies ({len(all_proxies)})\n# Updated: {utc}\n\n',  link_formatter),
        'proxy_links.txt':         (all_proxies, f'# Proxy links ({len(all_proxies)})\n# Updated: {utc}\n\n',          link_formatter),
        'proxy_links_clean.txt':   (all_proxies, f'# Clean proxy links ({len(all_proxies)})\n# Updated: {utc}\n\n',    link_formatter),
        'proxy_links_tme_clean.txt': (all_proxies, f'# Clean t.me proxy links ({len(all_proxies)})\n# Updated: {utc}\n\n', link_formatter),
    }

    for filename, (data, header, formatter) in files_data.items():
        with open(f'{args.output_dir}/{filename}', 'w', encoding='utf-8') as f:
            f.write(header + '\n'.join(formatter(x) for x in data))

    with open(f'{args.output_dir}/proxy_all_verified.json', 'w', encoding='utf-8') as f:
        json.dump(valid[:top], f, indent=2, ensure_ascii=False)

    with open(f'{args.output_dir}/proxies.json', 'w', encoding='utf-8') as f:
        json.dump(valid[:top], f, indent=2, ensure_ascii=False)

    stats = {
        "timestamp": utc.isoformat(),
        "total": len(valid),
        "by_region": {
            "ru": len(mtproto_ru), "eu": len(mtproto_eu),
            "us": len(mtproto_us), "asia": len(mtproto_asia),
            "socks5": len(socks5)
        },
        "top": top,
        "geoip_mode": GEOIP_MODE,
    }
    with open(f'{args.output_dir}/proxy_stats_verified.json', 'w', encoding='utf-8') as f:
        json.dump(stats, f, indent=2, ensure_ascii=False)

    with open(f'{args.output_dir}/source_stats.json', 'w', encoding='utf-8') as f:
        json.dump({"sources": SOURCES + SOCKS_SOURCES, "last_update": utc.isoformat()}, f, indent=2, ensure_ascii=False)

    with open(f'{args.output_dir}/verification.log', 'w', encoding='utf-8') as f:
        f.write(f"Verification completed at {utc}\n")
        f.write(f"GeoIP mode: {GEOIP_MODE}\n")
        f.write(f"Total proxies checked: {total}\n")
        f.write(f"Valid proxies found: {len(valid)}\n")
        f.write(f"Top saved: {top}\n")

    domain_proxies = [p for p in all_proxies if p.get('domain')]
    with open(f'{args.output_dir}/proxy_domain_verified.txt', 'w', encoding='utf-8') as f:
        f.write(f"# Proxies with domain ({len(domain_proxies)})\n# Updated: {utc}\n\n")
        for p in domain_proxies:
            f.write(f"{p['link']} # domain: {p['domain']}\n")

    elapsed = round(time.time() - start_time, 1)
    print('=' * 48)
    print(f'✅ MTProto RU: {len(mtproto_ru)}  EU: {len(mtproto_eu)}  US: {len(mtproto_us)}  ASIA: {len(mtproto_asia)}  SOCKS5: {len(socks5)}')
    if mtproto_ru:   print(f'🏆 Лучший RU: {mtproto_ru[0]["host"]}:{mtproto_ru[0]["port"]} ({mtproto_ru[0]["ping"]}s)')
    if mtproto_eu:   print(f'🏆 Лучший EU: {mtproto_eu[0]["host"]}:{mtproto_eu[0]["port"]} ({mtproto_eu[0]["ping"]}s)')
    if mtproto_us:   print(f'🏆 Лучший US: {mtproto_us[0]["host"]}:{mtproto_us[0]["port"]} ({mtproto_us[0]["ping"]}s)')
    if mtproto_asia: print(f'🏆 Лучший ASIA: {mtproto_asia[0]["host"]}:{mtproto_asia[0]["port"]} ({mtproto_asia[0]["ping"]}s)')
    if socks5:       print(f'🏆 Лучший SOCKS5: {socks5[0]["host"]}:{socks5[0]["port"]} ({socks5[0]["ping"]}s)')
    print(f'⏱️ Время: {elapsed}s')
    print('=' * 48)

def main():
    parser = argparse.ArgumentParser(description="MTProto & SOCKS5 Proxy Collector v3.7")
    parser.add_argument('--timeout', type=float, default=2.0)
    parser.add_argument('--workers', type=int, default=100)
    parser.add_argument('--top', type=int, default=0)
    parser.add_argument('--output-dir', default='verified')
    parser.add_argument('--manual', type=str)
    parser.add_argument('--geoip', type=str)
    parser.add_argument('--max-check', type=int, default=30000)
    parser.add_argument('--seen-file', type=str, default='verified/seen.json')
    parser.add_argument('--seen-ttl', type=int, default=48)
    args = parser.parse_args()
    run(args)

if __name__ == '__main__':
    main()
