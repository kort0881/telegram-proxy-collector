#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# MTProto & SOCKS5 Proxy Collector v3.1 (Quality Boost)

import requests
import re
import socket
import ssl
import concurrent.futures
import time
from datetime import datetime, timezone
import json
import os
import argparse
import asyncio
import base64
from pathlib import Path
from telethon.network import ConnectionTcpMTProxyRandomizedIntermediate

try:
    from telethon import TelegramClient
    from telethon.errors import FloodWaitError
    TELETHON_AVAILABLE = True
except ImportError:
    TELETHON_AVAILABLE = False
    print("⚠️ Telethon не установлен. Установите: pip install telethon")

API_ID   = os.environ.get("MTPROXY_API_ID")
API_HASH = os.environ.get("MTPROXY_API_HASH")

# ---------- MTProto источники (очищены от мусора) ----------
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
    "https://raw.githubusercontent.com/ProxyScrape/free-proxy-list/refs/heads/main/proxies/protocols/socks5/data.txt",
]

TIMEOUT = 2.0
RU_DOMAINS = ['.ru', 'yandex', 'vk.com', 'mail.ru', 'ok.ru', 'dzen', 'rutube', 'sber', 'tinkoff', 'vtb', 'gosuslugi', 'nalog', 'mos.ru', 'ozon', 'wildberries', 'avito', 'kinopoisk', 'mts', 'beeline']
BLOCKED = ['instagram', 'facebook', 'twitter', 'bbc', 'meduza', 'linkedin', 'torproject']
VERIFICATION_LOG = []

def _valid_port(p): return 1 <= int(p) <= 65535
def _is_blocked(secret, domain): return len(secret)<16 or (domain and any(b in domain for b in BLOCKED))
def _detect_region(domain): return 'ru' if domain and any(m in domain for m in RU_DOMAINS) else 'eu'
def _cleanup_session(host, port, delay=0.5):
    time.sleep(delay)
    for p in Path('.').glob(f'test_{host.replace(".", "_")}_{port}*'):
        try: p.unlink()
        except: pass

def _prepare_secret(s):
    s = s.strip()
    # Поддержка URL-safe base64
    s = s.replace('-', '+').replace('_', '/')
    if all(c in '0123456789abcdefABCDEF' for c in s):
        return bytes.fromhex(s)
    else:
        missing = len(s) % 4
        if missing:
            s += '=' * (4 - missing)
        return base64.b64decode(s)

def check_probe_resistance(host, port, expected_domain, timeout=10.0):
    if not expected_domain: return False
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=expected_domain) as ssock:
                req = f"GET / HTTP/1.1\r\nHost: {expected_domain}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n"
                ssock.sendall(req.encode())
                resp = ssock.recv(4096).decode(errors='ignore')
                if resp.startswith('HTTP/1.1') and ('Content-Length' in resp or 'text/html' in resp):
                    return True
    except: pass
    return False

def get_proxies_from_text(text):
    proxies = set()
    # MTProto
    for h,p,s in re.findall(r'tg://proxy\?server=([^&\s]+)&port=(\d+)&secret=([A-Za-z0-9_=+/%-]+)', text, re.I):
        if _valid_port(p): proxies.add(('mtproto', h, int(p), s))
    for h,p,s in re.findall(r't\.me/proxy\?server=([^&\s]+)&port=(\d+)&secret=([A-Za-z0-9_=+/%-]+)', text, re.I):
        if _valid_port(p): proxies.add(('mtproto', h, int(p), s))
    for h,p,s in re.findall(r'([A-Za-z0-9\.-]+):(\d+):([A-Fa-f0-9]{16,})', text):
        if _valid_port(p): proxies.add(('mtproto', h, int(p), s))
    # SOCKS5
    for h,p in re.findall(r'tg://socks\?server=([^&\s]+)&port=(\d+)', text, re.I):
        if _valid_port(p): proxies.add(('socks5', h, int(p), (None, None)))
    for u,pw,h,p in re.findall(r'socks5://(?:([^:@]+):([^@]+)@)?([A-Za-z0-9\.-]+):(\d+)', text, re.I):
        if _valid_port(p): proxies.add(('socks5', h, int(p), (u if u else None, pw if pw else None)))
    for h,p in re.findall(r'(\d+\.\d+\.\d+\.\d+):(\d+)', text):
        if _valid_port(p) and not any(x[1]==h and x[2]==int(p) for x in proxies if x[0]=='mtproto'):
            proxies.add(('socks5', h, int(p), (None, None)))
    # JSON
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
    
    # YAML парсинг (для all.yaml)
    if text.strip().startswith('proxies:'):
        try:
            import yaml
            data = yaml.safe_load(text)
            if isinstance(data, dict) and 'proxies' in data:
                for item in data['proxies']:
                    if item.get('type') == 'socks5':
                        server = item.get('server')
                        port = item.get('port')
                        if server and port and _valid_port(str(port)):
                            proxies.add(('socks5', server, int(port), (None, None)))
        except Exception:
            pass

    # Специальный парсинг для proxy.txt от CB-X2-Jun: socks5://IP:port:country
    for match in re.findall(r'(socks5)://([\d.]+):(\d+):\w+', text, re.I):
        protocol, ip, port = match
        if _valid_port(port):
            proxies.add(('socks5', ip, int(port), (None, None)))

    return proxies

def decode_domain(secret):
    if not secret.startswith('ee'): return None
    try:
        chars = []
        for i in range(2, len(secret)-1, 2):
            v = int(secret[i:i+2], 16)
            if v == 0: break
            if 32 <= v <= 126: chars.append(chr(v))
        return ''.join(chars).lower() or None
    except: return None

def fetch_source(url, timeout=15):
    for _ in range(3):
        try:
            r = requests.get(url, timeout=timeout)
            if r.status_code == 200: return r.text
        except: pass
        time.sleep(0.5)
    return ''

async def fetch_proxies_from_channel(channel, limit=50):
    if not TELETHON_AVAILABLE or not API_ID or not API_HASH: return set()
    proxies = set()
    client = TelegramClient('channel_reader_session', API_ID, API_HASH)
    try:
        await client.start()
        entity = channel.lstrip('@')
        chan = await client.get_entity(entity)
        print(f"📡 Читаем канал @{entity} (последние {limit})...")
        async for msg in client.iter_messages(chan, limit=limit):
            if msg.text: proxies.update(get_proxies_from_text(msg.text))
        print(f"  → Извлечено {len(proxies)} прокси")
    except FloodWaitError as e:
        print(f"  ⏳ FloodWait {e.seconds} сек")
        await asyncio.sleep(e.seconds)
    except Exception as e:
        print(f"  ✗ Ошибка: {e}")
    finally:
        await client.disconnect()
        for f in Path('.').glob('channel_reader_session*'):
            try: f.unlink()
            except: pass
    return proxies

async def check_mtproto(p, timeout_sec=10.0, max_attempts=2):
    _, host, port, secret = p
    domain = decode_domain(secret)
    if _is_blocked(secret, domain): return None
    try: secret_bytes = _prepare_secret(secret)
    except: return None

    for attempt in range(max_attempts):
        client = TelegramClient(f'test_{host.replace(".","_")}_{port}', API_ID, API_HASH,
                               connection=ConnectionTcpMTProxyRandomizedIntermediate,
                               proxy=(host, int(port), secret_bytes), timeout=timeout_sec)
        try:
            start = time.time()
            await asyncio.wait_for(client.connect(), timeout=timeout_sec)
            await asyncio.wait_for(client.get_config(), timeout=timeout_sec)
            ping = round(time.time()-start, 3)
            probe = check_probe_resistance(host, port, domain) if domain else False
            return {'type':'mtproto','host':host,'port':port,'secret':secret,
                    'link':f'tg://proxy?server={host}&port={port}&secret={secret}',
                    'ping':ping,'region':_detect_region(domain),'domain':domain or '',
                    'method':'Telethon_OK','probe_resistant':probe}
        except FloodWaitError as e:
            print(f"  ⏳ FloodWait {e.seconds} сек для {host}:{port}, ждём...")
            await asyncio.sleep(e.seconds)
            continue
        except Exception:
            return None
        finally:
            try: await client.disconnect()
            except: pass
            _cleanup_session(host, port)
    return None

async def check_socks5(p, timeout_sec=10.0, max_attempts=2):
    _, host, port, auth = p
    username, password = auth if auth else (None, None)
    proxy = (5, host, port, username, password)

    for attempt in range(max_attempts):
        client = TelegramClient(f'test_{host.replace(".","_")}_{port}', API_ID, API_HASH,
                               connection=ConnectionTcpMTProxyRandomizedIntermediate,
                               proxy=proxy, timeout=timeout_sec)
        try:
            start = time.time()
            await asyncio.wait_for(client.connect(), timeout=timeout_sec)
            await asyncio.wait_for(client.get_config(), timeout=timeout_sec)
            ping = round(time.time()-start, 3)
            return {'type':'socks5','host':host,'port':port,
                    'link':f'tg://socks?server={host}&port={port}',
                    'ping':ping,'region':'eu','domain':'','method':'Telethon_SOCKS5',
                    'probe_resistant':False}
        except FloodWaitError as e:
            print(f"  ⏳ FloodWait {e.seconds} сек для {host}:{port}, ждём...")
            await asyncio.sleep(e.seconds)
            continue
        except Exception:
            return None
        finally:
            try: await client.disconnect()
            except: pass
            _cleanup_session(host, port)
    return None

def check_proxy_tcp(p):
    typ, host, port, extra = p
    if typ == 'mtproto':
        secret = extra
        domain = decode_domain(secret)
        if _is_blocked(secret, domain): return None
        link = f'tg://proxy?server={host}&port={port}&secret={secret}'
        region = _detect_region(domain)
        domain_str = domain or ''
        probe = False
    else:
        link = f'tg://socks?server={host}&port={port}'
        region = 'eu'
        domain_str = ''
        probe = False
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(TIMEOUT)
            start = time.time()
            s.connect((host, port))
            ping = round(time.time()-start, 3)
        return {'type':typ,'host':host,'port':port,'secret':extra if typ=='mtproto' else None,
                'link':link,'ping':ping,'region':region,'domain':domain_str,
                'method':'TCP_OK','probe_resistant':probe}
    except: return None

def deduplicate_and_sort(proxies, max_ping=3.0):
    seen = set()
    unique = []
    for p in proxies:
        key = (p['type'], p['host'], p['port'], p.get('secret'))
        if key not in seen:
            seen.add(key)
            unique.append(p)
    # Фильтрация по пингу
    filtered = [p for p in unique if p['ping'] <= max_ping]
    filtered.sort(key=lambda x: (0 if (x['type']=='mtproto' and x.get('probe_resistant',False)) else 1 if x['type']=='mtproto' else 2, x['ping']))
    return filtered

def make_socks5_link(host, port): return f'tg://socks?server={host}&port={port}'

def load_local_proxies(file_path):
    proxies = set()
    if not os.path.isfile(file_path): return proxies
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            proxies = get_proxies_from_text(f.read())
        print(f"✓ Загружено {len(proxies)} прокси из {file_path}")
    except Exception as e: print(f"✗ Ошибка чтения {file_path}: {e}")
    return proxies

async def main_async(args):
    global TIMEOUT, API_ID, API_HASH, VERIFICATION_LOG
    VERIFICATION_LOG.clear()
    TIMEOUT = args.timeout
    if args.api_id: API_ID = args.api_id
    if args.api_hash: API_HASH = args.api_hash
    start = time.time()
    print('🚀 MTProxy Collector v3.1 (Quality Boost)')
    print('='*48)
    os.makedirs(args.output_dir, exist_ok=True)

    all_raw = set()
    print('\n📥 Сбор MTProto...')
    for url in SOURCES:
        name = (url.split('/')[-1] or url.split('/')[-2])[:42]
        text = fetch_source(url)
        if text:
            ext = get_proxies_from_text(text)
            cnt = sum(1 for x in ext if x[0]=='mtproto')
            all_raw.update(ext)
            print(f'  ✓ {name:<42} +{cnt} MTProto')
        else: print(f'  ✗ {name:<42} недоступен')

    print('\n📥 Сбор SOCKS5...')
    for url in SOCKS_SOURCES:
        name = (url.split('/')[-1] or url.split('/')[-2])[:42]
        text = fetch_source(url)
        if text:
            ext = get_proxies_from_text(text)
            cnt = sum(1 for x in ext if x[0]=='socks5')
            all_raw.update(ext)
            print(f'  ✓ {name:<42} +{cnt} SOCKS5')
        else: print(f'  ✗ {name:<42} недоступен')

    if args.manual:
        all_raw.update(load_local_proxies(args.manual))
    if args.channel:
        all_raw.update(await fetch_proxies_from_channel(args.channel, args.channel_limit))

    print(f'\n🧩 Уникальных прокси всего: {len(all_raw)}')
    if not all_raw:
        print('\n⚠️ Нет прокси. Завершение.')
        return

    print(f'\n⚡ Проверка {len(all_raw)} прокси...\n')
    valid = []
    checked = 0
    total = len(all_raw)
    use_telethon = TELETHON_AVAILABLE and API_ID and API_HASH

    if use_telethon:
        print('🔥 Режим: Telethon (полная проверка)\n')
        sem = asyncio.Semaphore(args.workers)
        async def check_one(p):
            async with sem:
                if p[0]=='mtproto': return await check_mtproto(p, args.timeout)
                else: return await check_socks5(p, args.timeout)
        tasks = [asyncio.create_task(check_one(p), name=f"{p[0]}_{p[1]}_{p[2]}") for p in all_raw]
        for task in asyncio.as_completed(tasks):
            res = await task
            checked += 1
            if res:
                valid.append(res)
            if checked % 100 == 0 or checked == total:
                print(f'  [{checked}/{total}] {checked/total*100:.0f}% | найдено: {len(valid)}')
    else:
        print('📡 Режим: TCP ping\n')
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as ex:
            futures = {ex.submit(check_proxy_tcp, p): p for p in all_raw}
            for f in concurrent.futures.as_completed(futures):
                res = f.result()
                checked += 1
                if res: valid.append(res)
                if checked % 100 == 0 or checked == total:
                    print(f'  [{checked}/{total}] {checked/total*100:.0f}% | найдено: {len(valid)}')

    if not valid:
        print('\n⚠️ Рабочих прокси не найдено.')
        return

    # Дедупликация, сортировка и фильтрация по пингу
    valid = deduplicate_and_sort(valid, args.max_ping)

    # Для RU-прокси оставляем только probe_resistant
    mtproto_ru = [x for x in valid if x['type']=='mtproto' and x['region']=='ru' and x.get('probe_resistant', False)]
    mtproto_eu = [x for x in valid if x['type']=='mtproto' and x['region']=='eu']
    socks5 = [x for x in valid if x['type']=='socks5']

    top = args.top if args.top>0 else None
    utc = datetime.now(timezone.utc)

    print(f'\n💾 Сохранение в {args.output_dir}/...')
    with open(f'{args.output_dir}/proxy_ru_verified.txt','w') as f:
        chunk = mtproto_ru[:top]
        f.write(f'# MTProto RU ({len(chunk)})\n# Updated: {utc}\n\n'+'\n'.join(x['link'] for x in chunk))
    with open(f'{args.output_dir}/proxy_eu_verified.txt','w') as f:
        chunk = mtproto_eu[:top]
        f.write(f'# MTProto EU ({len(chunk)})\n# Updated: {utc}\n\n'+'\n'.join(x['link'] for x in chunk))
    with open(f'{args.output_dir}/socks5_proxies.txt','w') as f:
        chunk = socks5[:top]
        f.write(f'# SOCKS5 ({len(chunk)})\n# Updated: {utc}\n\n'+'\n'.join(make_socks5_link(x['host'],x['port']) for x in chunk))
    with open(f'{args.output_dir}/proxy_all_verified.json','w') as f:
        json.dump(valid[:top], f, indent=2)

    # корневые файлы
    with open('proxy_ru.txt','w') as f: f.write('\n'.join(x['link'] for x in mtproto_ru[:top]))
    with open('proxy_eu.txt','w') as f: f.write('\n'.join(x['link'] for x in mtproto_eu[:top]))
    with open('proxy_all.txt','w') as f: f.write('\n'.join(x['link'] for x in (mtproto_ru+mtproto_eu)[:top]))
    with open('socks5.txt','w') as f: f.write('\n'.join(make_socks5_link(x['host'],x['port']) for x in socks5[:top]))

    elapsed = round(time.time()-start,1)
    print('='*48)
    print(f'✅ MTProto RU: {len(mtproto_ru)}  EU: {len(mtproto_eu)}  SOCKS5: {len(socks5)}')
    if mtproto_ru: print(f'🏆 Лучший RU: {mtproto_ru[0]["host"]}:{mtproto_ru[0]["port"]} ({mtproto_ru[0]["ping"]}s)')
    if mtproto_eu: print(f'🏆 Лучший EU: {mtproto_eu[0]["host"]}:{mtproto_eu[0]["port"]} ({mtproto_eu[0]["ping"]}s)')
    if socks5: print(f'🏆 Лучший SOCKS5: {socks5[0]["host"]}:{socks5[0]["port"]} ({socks5[0]["ping"]}s)')
    print(f'⏱️ Время: {elapsed}s')
    print('='*48)

def main():
    p = argparse.ArgumentParser()
    p.add_argument('--timeout', type=float, default=10.0, help='Таймаут на проверку (сек)')
    p.add_argument('--workers', type=int, default=25, help='Количество параллельных проверок')
    p.add_argument('--top', type=int, default=0, help='Максимальное число прокси в каждом файле (0 = все)')
    p.add_argument('--output-dir', default='verified')
    p.add_argument('--manual', help='Дополнительный файл с прокси')
    p.add_argument('--channel', help='Канал Telegram для чтения прокси')
    p.add_argument('--channel-limit', type=int, default=50, help='Сколько сообщений читать из канала')
    p.add_argument('--api-id', type=int, help='API ID Telegram')
    p.add_argument('--api-hash', help='API Hash Telegram')
    p.add_argument('--max-ping', type=float, default=3.0, help='Максимальный пинг (сек) для включения в финальный список')
    args = p.parse_args()
    if TELETHON_AVAILABLE and not (args.api_id or API_ID) and not (args.api_hash or API_HASH):
        print("⚠️ Для Telethon укажите --api-id и --api-hash или переменные окружения")
    asyncio.run(main_async(args))

if __name__ == '__main__':
    main()
