import requests
import re
import socket
import concurrent.futures
import time
from datetime import datetime
import json
import os
import glob
import argparse
import asyncio

try:
    from telethon import TelegramClient
    from telethon.connection import ConnectionTcpMTProxyRandomizedIntermediate
    TELETHON_AVAILABLE = True
except ImportError:
    TELETHON_AVAILABLE = False
    print("⚠️  Telethon не установлен. Используется TCP ping (pip install telethon для MTProto)")

# API ключи для Telethon (получи на my.telegram.org)
API_ID   = None  # Вставь свой api_id
API_HASH = None  # Вставь свой api_hash

SOURCES = [
    "https://raw.githubusercontent.com/SoliSpirit/mtproto/master/all_proxies.txt",
    "https://raw.githubusercontent.com/Grim1313/mtproto-for-telegram/refs/heads/master/all_proxies.txt",
    "https://raw.githubusercontent.com/ALIILAPRO/MTProtoProxy/main/mtproto.txt",
    "https://raw.githubusercontent.com/yemixzy/proxy-projects/main/proxies/mtproto.txt",
    "https://mtpro.xyz/api/?type=mtproto",
    "https://mtpro.xyz/api/?type=mtproto-ru",
]

TIMEOUT     = 2.0
MAX_WORKERS = 100

RU_DOMAINS = [
    '.ru', 'yandex', 'vk.com', 'mail.ru', 'ok.ru', 'dzen', 'rutube',
    'sber', 'tinkoff', 'vtb', 'gosuslugi', 'nalog', 'mos.ru',
    'ozon', 'wildberries', 'avito', 'kinopoisk', 'mts', 'beeline',
]

BLOCKED = [
    'instagram', 'facebook', 'twitter', 'bbc',
    'meduza', 'linkedin', 'torproject',
]


# ─────────────────────────── helpers ────────────────────────────

def _valid_port(port_str: str) -> bool:
    """Проверяет, что порт находится в допустимом диапазоне 1–65535."""
    try:
        return 1 <= int(port_str) <= 65535
    except (ValueError, TypeError):
        return False


def _is_blocked(secret: str, domain: str | None) -> bool:
    """True, если прокси нужно отфильтровать."""
    if len(secret) < 16:
        return True
    if domain and any(b in domain for b in BLOCKED):
        return True
    return False


def _detect_region(domain: str | None) -> str:
    """Определяет регион по домену в секрете."""
    if domain:
        for marker in RU_DOMAINS:
            if marker in domain:
                return 'ru'
    return 'eu'


def _cleanup_telethon_session(host: str, port: int) -> None:
    """Удаляет .session файлы, созданные Telethon."""
    session_name = f'test_{host.replace(".", "_")}_{port}'
    for path in glob.glob(f'{session_name}*'):
        try:
            os.remove(path)
        except OSError:
            pass


# ─────────────────────────── parsing ────────────────────────────

def get_proxies_from_text(text: str) -> set[tuple]:
    """
    Извлекает прокси из текста, поддерживая форматы:
    tg://proxy, t.me/proxy, host:port:secret и JSON.
    """
    proxies: set[tuple] = set()

    # tg://proxy?server=...&port=...&secret=...
    tg_pattern = re.compile(
        r'tg://proxy\?server=([^\s&]+)&port=(\d+)&secret=([A-Za-z0-9_=+/%-]+)',
        re.IGNORECASE,
    )
    for h, p, s in tg_pattern.findall(text):
        if _valid_port(p):
            proxies.add((h, int(p), s))

    # https://t.me/proxy?server=...&port=...&secret=...
    tme_pattern = re.compile(
        r't\.me/proxy\?server=([^\s&]+)&port=(\d+)&secret=([A-Za-z0-9_=+/%-]+)',
        re.IGNORECASE,
    )
    for h, p, s in tme_pattern.findall(text):
        if _valid_port(p):
            proxies.add((h, int(p), s))

    # host:port:secret
    simple_pattern = re.compile(
        r'([A-Za-z0-9\.-]+):(\d+):([A-Fa-f0-9]{16,})'
    )
    for h, p, s in simple_pattern.findall(text):
        if _valid_port(p):
            proxies.add((h, int(p), s))

    # JSON форматы
    txt = text.strip()
    if txt.startswith('[') or txt.startswith('{'):
        try:
            data = json.loads(txt)
            if isinstance(data, list):
                for item in data:
                    if isinstance(item, dict):
                        host   = item.get('host') or item.get('server')
                        port   = item.get('port')
                        secret = item.get('secret')
                        if host and port and secret and _valid_port(str(port)):
                            proxies.add((host, int(port), str(secret)))
        except Exception:
            pass

    return proxies


def decode_domain(secret: str) -> str | None:
    """Декодирует домен из MTProto-секрета с префиксом ee."""
    if not secret.startswith('ee'):
        return None
    try:
        chars = []
        for i in range(2, len(secret) - 1, 2):
            val = int(secret[i:i + 2], 16)
            if val == 0:
                break
            # Только печатаемые ASCII символы
            if 32 <= val <= 126:
                chars.append(chr(val))
        result = ''.join(chars).lower()
        return result if result else None
    except Exception:
        return None


# ──────────────────────── source fetching ───────────────────────

def fetch_source(url: str, timeout: int = 15) -> str:
    """Скачивает источник с 3 попытками и экспоненциальной паузой."""
    for attempt in range(3):
        try:
            r = requests.get(url, timeout=timeout)
            if r.status_code == 200:
                return r.text
        except Exception:
            pass
        time.sleep(0.5 * (attempt + 1))
    return ''


# ─────────────────────────── checkers ───────────────────────────

async def check_proxy_telethon(p: tuple) -> dict | None:
    if not TELETHON_AVAILABLE or not API_ID or not API_HASH:
        return None

    host, port, secret = p
    domain = decode_domain(secret)

    if _is_blocked(secret, domain):
        return None

    client = TelegramClient(
        f'test_{host.replace(".", "_")}_{port}', API_ID, API_HASH,
        connection=ConnectionTcpMTProxyRandomizedIntermediate,
        proxy=(host, int(port), secret),
        timeout=8.0,
    )
    try:
        start = time.time()
        await client.connect()
        await client.get_config()
        ping = round(time.time() - start, 3)
        return {
            'host': host, 'port': port, 'secret': secret,
            'link': f'tg://proxy?server={host}&port={port}&secret={secret}',
            'ping': ping, 'region': _detect_region(domain),
            'domain': domain or '', 'method': 'Telethon_OK',
        }
    except Exception:
        return None
    finally:
        try:
            await client.disconnect()
        except Exception:
            pass
        _cleanup_telethon_session(host, port)


def check_proxy_tcp(p: tuple) -> dict | None:
    host, port, secret = p
    domain = decode_domain(secret)

    if _is_blocked(secret, domain):
        return None

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(TIMEOUT)
            start = time.time()
            s.connect((host, port))
            ping = round(time.time() - start, 3)
    except Exception:
        return None

    return {
        'host': host, 'port': port, 'secret': secret,
        'link': f'tg://proxy?server={host}&port={port}&secret={secret}',
        'ping': ping, 'region': _detect_region(domain),
        'domain': domain or '', 'method': 'TCP_OK',
    }


# ─────────────────────────── postprocess ────────────────────────

def deduplicate_by_host_port(proxies: list[dict]) -> list[dict]:
    """Оставляет только самый быстрый прокси для каждой пары (host, port)."""
    best: dict[tuple, dict] = {}
    for p in proxies:
        key = (p['host'], p['port'])
        if key not in best or p['ping'] < best[key]['ping']:
            best[key] = p
    return list(best.values())


def make_tme_link(host: str, port: int, secret: str) -> str:
    return f'https://t.me/proxy?server={host}&port={port}&secret={secret}'


# ─────────────────────────── main ───────────────────────────────

async def main_async(args: argparse.Namespace) -> None:
    start_time = time.time()
    print('🚀 MTProto Proxy Collector v2.1')
    print('=' * 48)

    output_dir = args.output_dir
    os.makedirs(output_dir, exist_ok=True)

    # ── сбор прокси ──────────────────────────────────────────────
    print('\n📥 Сбор прокси из источников...\n')
    all_raw: set[tuple] = set()

    for url in SOURCES:
        name = (url.split('/')[-1] or url.split('/')[-2])[:42]
        text = fetch_source(url)
        if text:
            extracted = get_proxies_from_text(text)
            all_raw.update(extracted)
            print(f'  ✓ {name:<42} +{len(extracted)}')
        else:
            print(f'  ✗ {name:<42} недоступен')

    print(f'\n  Уникальных прокси: {len(all_raw)}\n')

    # ── проверка прокси ───────────────────────────────────────────
    print(f'⚡ Проверка {len(all_raw)} прокси...\n')

    valid:   list[dict] = []
    checked: int        = 0
    total:   int        = len(all_raw)

    if TELETHON_AVAILABLE and API_ID and API_HASH:
        print('🔥 Режим: Telethon MTProto\n')
        semaphore = asyncio.Semaphore(10)

        async def check_p(p: tuple) -> dict | None:
            async with semaphore:
                return await check_proxy_telethon(p)

        tasks = [asyncio.ensure_future(check_p(p)) for p in all_raw]
        for coro in asyncio.as_completed(tasks):
            result = await coro
            checked += 1
            if result:
                valid.append(result)
            if checked % 50 == 0 or checked == total:
                print(f'  [{checked}/{total}] {checked / total * 100:.0f}% | найдено: {len(valid)}')

    else:
        print('📡 Режим: TCP ping\n')
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as exc:
            futures = {exc.submit(check_proxy_tcp, p): p for p in all_raw}
            for f in concurrent.futures.as_completed(futures):
                result = f.result()
                checked += 1
                if result:
                    valid.append(result)
                if checked % 100 == 0 or checked == total:
                    print(f'  [{checked}/{total}] {checked / total * 100:.0f}% | найдено: {len(valid)}')

    # ── постобработка ─────────────────────────────────────────────
    valid = deduplicate_by_host_port(valid)
    ru    = sorted([x for x in valid if x['region'] == 'ru'], key=lambda x: x['ping'])
    eu    = sorted([x for x in valid if x['region'] == 'eu'], key=lambda x: x['ping'])

    top_n = args.top if args.top > 0 else None

    # ── сохранение файлов ─────────────────────────────────────────
    print(f'\n💾 Сохранение в {output_dir}/...\n')

    region_files: dict[str, list[dict]] = {
        f'{output_dir}/proxy_ru_verified.txt':  ru,
        f'{output_dir}/proxy_eu_verified.txt':  eu,
        f'{output_dir}/proxy_all_verified.txt': valid,
    }

    for filename, proxies_list in region_files.items():
        region_label = 'RU' if 'ru' in filename else 'EU' if 'eu' in filename else 'All'
        chunk = proxies_list[:top_n]
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(f'# Verified {region_label} Proxies ({len(chunk)})\n')
            f.write(f'# Updated: {datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")}\n')
            if chunk:
                f.write(f'# Method: {chunk[0]["method"]}\n')
                f.write(f'# Best ping: {chunk[0]["ping"]}s\n')
            f.write('\n')
            f.write('\n'.join(x['link'] for x in chunk))

    # t.me формат
    tme_chunk = valid[:top_n]
    with open(f'{output_dir}/proxy_all_tme_verified.txt', 'w', encoding='utf-8') as f:
        f.write(f'# Verified Proxies t.me format ({len(tme_chunk)})\n')
        f.write(f'# Updated: {datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")}\n\n')
        for x in tme_chunk:
            f.write(make_tme_link(x['host'], x['port'], x['secret']) + '\n')

    # ЧИСТЫЙ файл только с tg:// (для копипаста с мобилы)
    clean_chunk = valid[:top_n]
    with open(f'{output_dir}/proxy_links_clean.txt', 'w', encoding='utf-8') as f:
        for x in clean_chunk:
            f.write(f'tg://proxy?server={x["host"]}&port={x["port"]}&secret={x["secret"]}\n')

    # ЧИСТЫЙ файл только с https://t.me/proxy (максимальная кликабельность)
    with open(f'{output_dir}/proxy_links_tme_clean.txt', 'w', encoding='utf-8') as f:
        for x in clean_chunk:
            f.write(make_tme_link(x['host'], x['port'], x['secret']) + '\n')

    # Полный JSON с деталями каждого прокси
    json_chunk = valid[:top_n]
    with open(f'{output_dir}/proxy_all_verified.json', 'w', encoding='utf-8') as f:
        json.dump(json_chunk, f, indent=2, ensure_ascii=False)

    # Статистика
    elapsed = round(time.time() - start_time, 1)
    stats = {
        'timestamp_utc':   datetime.utcnow().isoformat(),
        'total_raw':       len(all_raw),
        'total_verified':  len(valid),
        'ru_count':        len(ru),
        'eu_count':        len(eu),
        'telethon_used':   TELETHON_AVAILABLE and bool(API_ID and API_HASH),
        'best_ru_ping':    ru[0]['ping'] if ru else None,
        'best_eu_ping':    eu[0]['ping'] if eu else None,
        'execution_time':  elapsed,
        'sources_count':   len(SOURCES),
        'workers':         args.workers,
    }
    with open(f'{output_dir}/proxy_stats_verified.json', 'w', encoding='utf-8') as f:
        json.dump(stats, f, indent=2, ensure_ascii=False)

    print('=' * 48)
    print(f'✅  Верифицировано: RU={len(ru)}  EU={len(eu)}  Всего={len(valid)}')
    if ru:
        print(f'🏆  Лучший RU: {ru[0]["host"]}:{ru[0]["port"]}  ({ru[0]["ping"]}s)')
    if eu:
        print(f'🏆  Лучший EU: {eu[0]["host"]}:{eu[0]["port"]}  ({eu[0]["ping"]}s)')
    print(f'📁  Результаты: {output_dir}/')
    print(f'⏱️   Время:      {elapsed}s')
    print('=' * 48)


def main() -> None:
    parser = argparse.ArgumentParser(description='🚀 MTProto Proxy Collector v2.1')
    parser.add_argument('--timeout',    type=float, default=2.0,        help='TCP таймаут (сек)')
    parser.add_argument('--workers',    type=int,   default=100,        help='Потоки TCP проверки')
    parser.add_argument('--top',        type=int,   default=0,          help='Сохранить TOP N быстрейших (0 = все)')
    parser.add_argument('--output-dir', type=str,   default='verified', help='Папка для результатов')
    args = parser.parse_args()

    global TIMEOUT
    TIMEOUT = args.timeout

    asyncio.run(main_async(args))


if __name__ == '__main__':
    main()
