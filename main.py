#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# MTProto & SOCKS5 Proxy Collector v3.8.3 (Final stable)

import requests
import re
import socket
import concurrent.futures
import time
from datetime import datetime, timezone
import json
import os
import argparse
import asyncio
import base64
from telethon.network import ConnectionTcpMTProxyRandomizedIntermediate
from telethon.sessions import MemorySession

try:
    from telethon import TelegramClient
    from telethon.errors import FloodWaitError, RPCError
    TELETHON_AVAILABLE = True
except ImportError:
    TELETHON_AVAILABLE = False
    print("⚠️ Telethon не установлен. Установите: pip install telethon")

API_ID   = os.environ.get("MTPROXY_API_ID")
API_HASH = os.environ.get("MTPROXY_API_HASH")

MAX_SOCKS5_TO_CHECK = 20000

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
    "https://proxylist.geonode.com/api/proxy-list?limit=300&page=1&sort_by=lastChecked&sort_type=desc&protocols=http,https",
    "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=10000&country=all&ssl=all&anonymity=all",
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
    "https://raw.githubusercontent.com/ProxyScrape/free-proxy-list/refs/heads/main/proxies/protocols/socks5/data.txt",
]

TIMEOUT = 2.0
RU_DOMAINS = ['.ru', 'yandex', 'vk.com', 'mail.ru', 'ok.ru', 'dzen', 'rutube', 'sber',
              'tinkoff', 'vtb', 'gosuslugi', 'nalog', 'mos.ru', 'ozon', 'wildberries',
              'avito', 'kinopoisk', 'mts', 'beeline']
BLOCKED = ['instagram', 'facebook', 'twitter', 'bbc', 'meduza', 'linkedin', 'torproject']

DEBUG_PRINTED = False

def _valid_port(p): return 1 <= int(p) <= 65535
def _is_blocked(secret, domain):
    return len(secret) < 16 or (domain and any(b in domain for b in BLOCKED))
def _detect_region(domain):
    return 'ru' if domain and any(m in domain for m in RU_DOMAINS) else 'eu'

def _prepare_secret(s):
    if isinstance(s, (bytes, bytearray)):
        try:
            s = s.decode('utf-8')
        except UnicodeDecodeError:
            return None
    if not isinstance(s, str):
        return None
    s = s.strip().replace('-', '+').replace('_', '/')
    if re.fullmatch(r'[0-9a-fA-F]+', s):
        if len(s) % 2 != 0:
            return None
        try:
            return bytes.fromhex(s)
        except ValueError:
            return None
    missing = (4 - len(s) % 4) % 4
    s += '=' * missing
    try:
        return base64.b64decode(s)
    except Exception:
        return None

def get_proxies_from_text(text):
    proxies = set()
    for h, p, s in re.findall(r'tg://proxy\?server=([^&\s]+)&port=(\d+)&secret=([A-Za-z0-9_=+/%-]+)', text, re.I):
        if _valid_port(p): proxies.add(('mtproto', h, int(p), s))
    for h, p, s in re.findall(r't\.me/proxy\?server=([^&\s]+)&port=(\d+)&secret=([A-Za-z0-9_=+/%-]+)', text, re.I):
        if _valid_port(p): proxies.add(('mtproto', h, int(p), s))
    for h, p, s in re.findall(r'([A-Za-z0-9\.-]+):(\d+):([A-Fa-f0-9]{16,})', text):
        if _valid_port(p): proxies.add(('mtproto', h, int(p), s))
    for h, p in re.findall(r'tg://socks\?server=([^&\s]+)&port=(\d+)', text, re.I):
        if _valid_port(p): proxies.add(('socks5', h, int(p), (None, None)))
    for u, pw, h, p in re.findall(r'socks5://(?:([^:@]+):([^@]+)@)?([A-Za-z0-9\.-]+):(\d+)', text, re.I):
        if _valid_port(p): proxies.add(('socks5', h, int(p), (u or None, pw or None)))
    for h, p in re.findall(r'(\d+\.\d+\.\d+\.\d+):(\d+)', text):
        if _valid_port(p) and not any(x[1] == h and x[2] == int(p) for x in proxies if x[0] == 'mtproto'):
            proxies.add(('socks5', h, int(p), (None, None)))
    txt = text.strip()
    if txt.startswith('[') or txt.startswith('{'):
        try:
            data = json.loads(txt)
            if isinstance(data, list):
                for item in data:
                    if isinstance(item, dict):
                        if 'host' in item and 'port' in item and 'secret' in item:
                            proxies.add(('mtproto', item['host'], int(item['port']), str(item['secret'])))
                        if 'socks5' in str(item).lower() and ('ip' in item or 'host' in item) and 'port' in item:
                            proxies.add(('socks5', item.get('ip') or item.get('host'), int(item['port']), (None, None)))
        except: pass
    if txt.startswith('proxies:'):
        try:
            import yaml
            data = yaml.safe_load(txt)
            if isinstance(data, dict) and 'proxies' in data:
                for item in data['proxies']:
                    if item.get('type') == 'socks5':
                        server, port = item.get('server'), item.get('port')
                        if server and port and _valid_port(str(port)):
                            proxies.add(('socks5', server, int(port), (None, None)))
        except: pass
    for match in re.findall(r'(socks5)://([\d.]+):(\d+):\w+', text, re.I):
        _, ip, port = match
        if _valid_port(port):
            proxies.add(('socks5', ip, int(port), (None, None)))
    return proxies

def decode_domain(secret):
    if isinstance(secret, bytes):
        try:
            secret = secret.decode('utf-8')
        except UnicodeDecodeError:
            return None
    if not secret.startswith('ee'): return None
    try:
        chars = []
        for i in range(2, len(secret)-1, 2):
            v = int(secret[i:i+2], 16)
            if v == 0: break
            if 32 <= v <= 126: chars.append(chr(v))
        return ''.join(chars).lower() or None
    except: return None

def fetch_source(url, timeout=8):
    try:
        r = requests.get(url, timeout=timeout)
        if r.status_code == 200: return r.text
    except: pass
    return ''

def fetch_sources_parallel(urls, timeout=8, workers=50):
    results = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        future_to_url = {ex.submit(fetch_source, url, timeout): url for url in urls}
        for future in concurrent.futures.as_completed(future_to_url):
            url = future_to_url[future]
            results[url] = future.result()
    return results

def check_socks5_fast(host, port, timeout=3.0):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        sock.send(b'\x05\x01\x00')
        data = sock.recv(2)
        sock.close()
        return data == b'\x05\x00'
    except:
        return False

async def check_mtproto(p, timeout_sec=30.0):
    global DEBUG_PRINTED
    _, host, port, secret = p
    if isinstance(secret, bytes):
        try:
            secret = secret.decode('utf-8')
        except UnicodeDecodeError:
            return None
    domain = decode_domain(secret)
    if _is_blocked(secret, domain):
        return None
    secret_bytes = _prepare_secret(secret)
    if secret_bytes is None:
        return None

    client = TelegramClient(
        MemorySession(),
        API_ID, API_HASH,
        connection=ConnectionTcpMTProxyRandomizedIntermediate,
        proxy=(host, int(port), secret_bytes),
        timeout=timeout_sec,
        request_retries=0,
        connection_retries=0,
        retry_delay=0,
        auto_reconnect=False,
    )
    # ⚡ start объявлен ДО try, чтобы быть доступным в except RPCError
    start = time.time()
    try:
        await asyncio.wait_for(client.connect(), timeout=timeout_sec)
        # Реальный запрос к Telegram — если доходит, прокси рабочий
        await asyncio.wait_for(client.get_me(), timeout=timeout_sec)
        ping = round(time.time() - start, 3)
        return {
            'type': 'mtproto', 'host': host, 'port': port, 'secret': secret,
            'link': f'tg://proxy?server={host}&port={port}&secret={secret}',
            'ping': ping, 'region': _detect_region(domain),
            'domain': domain or '', 'method': 'Telethon_OK',
            'probe_resistant': False,
        }
    except asyncio.TimeoutError:
        return None
    except FloodWaitError as e:
        print(f"⚠️ FloodWait для {host}:{port} – {e.seconds}с")
        return None
    except RPCError:
        # RPCError означает, что запрос дошёл до Telegram, прокси работает
        ping = round(time.time() - start, 3)
        return {
            'type': 'mtproto', 'host': host, 'port': port, 'secret': secret,
            'link': f'tg://proxy?server={host}&port={port}&secret={secret}',
            'ping': ping, 'region': _detect_region(domain),
            'domain': domain or '', 'method': 'Telethon_RPC',
            'probe_resistant': False,
        }
    except Exception as e:
        if not DEBUG_PRINTED:
            DEBUG_PRINTED = True
            print(f"⚠️ Ошибка для {host}:{port} – {type(e).__name__}: {str(e)[:100]}")
        return None
    finally:
        try:
            await client.disconnect()
        except:
            pass

async def fetch_proxies_from_channel(channel, limit=50):
    if not TELETHON_AVAILABLE or not API_ID or not API_HASH:
        return set()
    proxies = set()
    client = TelegramClient(MemorySession(), API_ID, API_HASH)
    try:
        await client.start()
        entity = channel.lstrip('@')
        chan = await client.get_entity(entity)
        print(f"📡 Читаем канал @{entity} (последние {limit})...")
        async for msg in client.iter_messages(chan, limit=limit):
            if msg.text:
                proxies.update(get_proxies_from_text(msg.text))
        print(f"  → Извлечено {len(proxies)} прокси")
    except FloodWaitError as e:
        print(f"  ⏳ FloodWait {e.seconds} сек")
        await asyncio.sleep(min(e.seconds, 5))
    except Exception as e:
        print(f"  ✗ Ошибка: {e}")
    finally:
        await client.disconnect()
    return proxies

def check_proxy_tcp(p):
    typ, host, port, extra = p
    if typ == 'mtproto':
        secret = extra
        if isinstance(secret, bytes):
            try:
                secret = secret.decode('utf-8')
            except UnicodeDecodeError:
                return None
        domain = decode_domain(secret)
        if _is_blocked(secret, domain): return None
        link = f'tg://proxy?server={host}&port={port}&secret={secret}'
        region = _detect_region(domain)
        domain_str = domain or ''
    else:
        link = f'tg://socks?server={host}&port={port}'
        region, domain_str = 'eu', ''
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(TIMEOUT)
            start = time.time()
            s.connect((host, port))
            ping = round(time.time() - start, 3)
        return {
            'type': typ, 'host': host, 'port': port,
            'secret': extra if typ == 'mtproto' else None,
            'link': link, 'ping': ping, 'region': region,
            'domain': domain_str, 'method': 'TCP_OK', 'probe_resistant': False,
        }
    except:
        return None

def deduplicate_and_sort(proxies, max_ping=5.0):
    seen, unique = set(), []
    for p in proxies:
        key = (p['type'], p['host'], p['port'], p.get('secret'))
        if key not in seen:
            seen.add(key); unique.append(p)
    filtered = [p for p in unique if p['ping'] <= max_ping]
    filtered.sort(key=lambda x: (0 if x['type'] == 'mtproto' else 1, x['ping']))
    return filtered

def make_socks5_link(host, port): return f'tg://socks?server={host}&port={port}'

def load_local_proxies(file_path):
    proxies = set()
    if not os.path.isfile(file_path): return proxies
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            proxies = get_proxies_from_text(f.read())
        print(f"✓ Загружено {len(proxies)} прокси из {file_path}")
    except Exception as e:
        print(f"✗ Ошибка чтения {file_path}: {e}")
    return proxies

async def main_async(args):
    global TIMEOUT, API_ID, API_HASH, DEBUG_PRINTED
    TIMEOUT = args.timeout
    if args.api_id: API_ID = args.api_id
    if args.api_hash: API_HASH = args.api_hash
    start = time.time()
    DEBUG_PRINTED = False
    print('🚀 MTProxy Collector v3.8.3 (Final stable)')
    print('=' * 48)
    os.makedirs(args.output_dir, exist_ok=True)

    print('\n📥 Параллельная загрузка источников...')
    all_urls = SOURCES + SOCKS_SOURCES
    url_results = fetch_sources_parallel(all_urls, timeout=8, workers=50)

    all_raw = set()
    for url, text in url_results.items():
        if text:
            ext = get_proxies_from_text(text)
            all_raw.update(ext)
        else:
            name = (url.split('/')[-1] or url.split('/')[-2])[:42]
            print(f'  ✗ {name} недоступен')

    if args.manual:
        all_raw.update(load_local_proxies(args.manual))
    if args.channel:
        all_raw.update(await fetch_proxies_from_channel(args.channel, args.channel_limit))

    mtproto_set = {p for p in all_raw if p[0] == 'mtproto'}
    socks5_set  = {p for p in all_raw if p[0] == 'socks5'}

    if len(socks5_set) > MAX_SOCKS5_TO_CHECK:
        socks5_set = set(list(socks5_set)[:MAX_SOCKS5_TO_CHECK])
        print(f"⚠️ SOCKS5 ограничены до {MAX_SOCKS5_TO_CHECK}")

    all_raw = mtproto_set | socks5_set
    print(f'\n🧩 Уникальных прокси: {len(all_raw)} (MTProto: {len(mtproto_set)}, SOCKS5: {len(socks5_set)})')

    if not all_raw:
        print('\n⚠️ Нет прокси. Завершение.')
        return

    print(f'\n⚡ Проверка {len(all_raw)} прокси...')
    valid = []
    mtproto_list = [p for p in all_raw if p[0] == 'mtproto']
    socks5_list  = [p for p in all_raw if p[0] == 'socks5']

    if TELETHON_AVAILABLE and API_ID and API_HASH and mtproto_list:
        print(f'🔥 MTProto: Telethon (workers={args.workers}, timeout={args.timeout_mt}s)')
        sem = asyncio.Semaphore(args.workers)
        async def check_one_mt(p):
            async with sem:
                return await check_mtproto(p, args.timeout_mt)
        tasks = [asyncio.create_task(check_one_mt(p)) for p in mtproto_list]

        checked_mt = 0
        for task in asyncio.as_completed(tasks):
            res = await task
            checked_mt += 1
            if res:
                valid.append(res)
            found_mt = len([v for v in valid if v['type'] == 'mtproto'])
            if checked_mt % 200 == 0 or checked_mt == len(mtproto_list):
                print(f'  MTProto: {checked_mt}/{len(mtproto_list)} | найдено: {found_mt}')
    else:
        print('📡 MTProto: TCP fallback')
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as ex:
            futures = {ex.submit(check_proxy_tcp, p): p for p in mtproto_list}
            for f in concurrent.futures.as_completed(futures):
                res = f.result()
                if res:
                    valid.append(res)

    if socks5_list:
        print(f'🔒 SOCKS5: TCP fast check (workers={args.workers_socks})')
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers_socks) as ex:
            future_to_socks = {ex.submit(check_socks5_fast, h, int(p), args.timeout_socks): (h, p) for _, h, p, _ in socks5_list}

            checked_s = 0
            for future in concurrent.futures.as_completed(future_to_socks):
                host, port = future_to_socks[future]
                checked_s += 1
                if future.result():
                    valid.append({
                        'type': 'socks5', 'host': host, 'port': port,
                        'link': f'tg://socks?server={host}&port={port}',
                        'ping': 0.1, 'region': 'eu', 'domain': '',
                        'method': 'TCP_SOCKS5_OK', 'probe_resistant': False
                    })
                found_s = len([v for v in valid if v['type'] == 'socks5'])
                if checked_s % 500 == 0 or checked_s == len(socks5_list):
                    print(f'  SOCKS5: {checked_s}/{len(socks5_list)} | найдено: {found_s}')

    if not valid:
        print('\n⚠️ Рабочих прокси не найдено.')
        return

    valid = deduplicate_and_sort(valid, args.max_ping)
    mtproto_ru = [x for x in valid if x['type'] == 'mtproto' and x['region'] == 'ru']
    mtproto_eu = [x for x in valid if x['type'] == 'mtproto' and x['region'] == 'eu']
    socks5     = [x for x in valid if x['type'] == 'socks5']

    top = args.top if args.top > 0 else None
    utc = datetime.now(timezone.utc)

    print(f'\n💾 Сохранение в {args.output_dir}/...')
    saves = {
        f'{args.output_dir}/proxy_ru_verified.txt': (
            f'# MTProto RU ({len(mtproto_ru[:top])})\n# Updated: {utc}\n\n'
            + '\n'.join(x['link'] for x in mtproto_ru[:top])
        ),
        f'{args.output_dir}/proxy_eu_verified.txt': (
            f'# MTProto EU ({len(mtproto_eu[:top])})\n# Updated: {utc}\n\n'
            + '\n'.join(x['link'] for x in mtproto_eu[:top])
        ),
        f'{args.output_dir}/socks5_proxies.txt': (
            f'# SOCKS5 ({len(socks5[:top])})\n# Updated: {utc}\n\n'
            + '\n'.join(make_socks5_link(x['host'], x['port']) for x in socks5[:top])
        ),
        'proxy_ru.txt':  '\n'.join(x['link'] for x in mtproto_ru[:top]),
        'proxy_eu.txt':  '\n'.join(x['link'] for x in mtproto_eu[:top]),
        'proxy_all.txt': '\n'.join(x['link'] for x in (mtproto_ru + mtproto_eu)[:top]),
        'socks5.txt':    '\n'.join(make_socks5_link(x['host'], x['port']) for x in socks5[:top]),
    }
    for path, content in saves.items():
        with open(path, 'w') as f:
            f.write(content)
    with open(f'{args.output_dir}/proxy_all_verified.json', 'w') as f:
        json.dump(valid[:top], f, indent=2)

    elapsed = round(time.time() - start, 1)
    print('=' * 48)
    print(f'✅ MTProto RU: {len(mtproto_ru)}  EU: {len(mtproto_eu)}  SOCKS5: {len(socks5)}')
    if mtproto_ru: print(f'🏆 Лучший RU: {mtproto_ru[0]["host"]}:{mtproto_ru[0]["port"]} ({mtproto_ru[0]["ping"]}s)')
    if mtproto_eu: print(f'🏆 Лучший EU: {mtproto_eu[0]["host"]}:{mtproto_eu[0]["port"]} ({mtproto_eu[0]["ping"]}s)')
    if socks5:     print(f'🏆 Лучший SOCKS5: {socks5[0]["host"]}:{socks5[0]["port"]} ({socks5[0]["ping"]}s)')
    print(f'⏱️ Время: {elapsed}s')
    print('=' * 48)

def main():
    p = argparse.ArgumentParser()
    p.add_argument('--timeout', type=float, default=2.0)
    p.add_argument('--timeout-mt', type=float, default=30.0)
    p.add_argument('--timeout-socks', type=float, default=3.0)
    p.add_argument('--workers', type=int, default=200)
    p.add_argument('--workers-socks', type=int, default=300)
    p.add_argument('--top', type=int, default=0)
    p.add_argument('--output-dir', default='verified')
    p.add_argument('--manual')
    p.add_argument('--channel')
    p.add_argument('--channel-limit', type=int, default=50)
    p.add_argument('--api-id', type=int)
    p.add_argument('--api-hash')
    p.add_argument('--max-ping', type=float, default=5.0)
    args = p.parse_args()
    asyncio.run(main_async(args))

if __name__ == '__main__':
    main()
