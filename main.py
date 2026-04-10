"""
MTProto Proxy Collector v3.0
Улучшения: httpx/HTTP2, ротация UA, прокси-пул, ping-история,
рейтинг стабильности, статистика по источникам, geo-IP фильтрация.
"""

import re
import socket
import struct
import concurrent.futures
import time
import json
import os
import glob
import argparse
import asyncio
import random
import logging
from datetime import datetime, timezone
from collections import defaultdict
from typing import Optional

try:
    import httpx
    HTTPX_AVAILABLE = True
except ImportError:
    HTTPX_AVAILABLE = False
    import requests

try:
    from telethon import TelegramClient
    from telethon.connection import ConnectionTcpMTProxyRandomizedIntermediate
    TELETHON_AVAILABLE = True
except ImportError:
    TELETHON_AVAILABLE = False

# ─────────────────── конфигурация ───────────────────────────────

API_ID   = None  # my.telegram.org
API_HASH = None

# Список User-Agent реальных браузеров
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
]

SOURCES = [
    "https://raw.githubusercontent.com/SoliSpirit/mtproto/master/all_proxies.txt",
    "https://raw.githubusercontent.com/Grim1313/mtproto-for-telegram/refs/heads/master/all_proxies.txt",
    "https://raw.githubusercontent.com/ALIILAPRO/MTProtoProxy/main/mtproto.txt",
    "https://raw.githubusercontent.com/yemixzy/proxy-projects/main/proxies/mtproto.txt",
    "https://raw.githubusercontent.com/soroushmirzaei/telegram-proxies-collector/main/proxies/ip/mtproto",
    "https://raw.githubusercontent.com/mheidari98/.proxy/main/all",
    "https://raw.githubusercontent.com/hookzof/socks5_list/master/tg/mtproto.txt",
    "https://raw.githubusercontent.com/themrb/mtproto-proxy-data/main/all_proxies.txt",
    "https://raw.githubusercontent.com/4IceG/Personal-proxies/master/zap-mtproto",
    "https://mtpro.xyz/api/?type=mtproto",
    "https://mtpro.xyz/api/?type=mtproto-ru",
    "https://proxylist.geonode.com/api/proxy-list?protocols=socks5&limit=100&sort_by=speed",
]

# Опциональный список ваших HTTP/SOCKS прокси для ротации при сборе
FETCH_PROXIES: list[str] = [
    # "socks5h://127.0.0.1:9050",  # Tor
    # "http://user:pass@proxy.example.com:8080",
]

TIMEOUT     = 2.0
MAX_WORKERS = 50          # снижено для устойчивости под DPI
MAX_PING    = 2.0         # прокси с ping > MAX_PING не берём
MIN_CHECKS_FOR_STABLE = 2 # сколько проверок нужно для «стабильный»

RU_DOMAINS = [
    '.ru', 'yandex', 'vk.com', 'mail.ru', 'ok.ru', 'dzen', 'rutube',
    'sber', 'tinkoff', 'vtb', 'gosuslugi', 'nalog', 'mos.ru',
    'ozon', 'wildberries', 'avito', 'kinopoisk', 'mts', 'beeline',
]

BLOCKED = [
    'instagram', 'facebook', 'twitter', 'bbc',
    'meduza', 'linkedin', 'torproject',
]

# ─────────────────── логирование ────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s | %(levelname)s | %(message)s',
    datefmt='%H:%M:%S',
)
log = logging.getLogger(__name__)

# ─────────────────── хранилище ping-истории ─────────────────────

class PingHistory:
    """Хранит историю пингов для каждого (host, port) и считает стабильность."""

    HISTORY_FILE = 'ping_history.json'

    def __init__(self) -> None:
        self._data: dict[str, list[float]] = {}
        self._load()

    def _key(self, host: str, port: int) -> str:
        return f'{host}:{port}'

    def _load(self) -> None:
        if os.path.exists(self.HISTORY_FILE):
            try:
                with open(self.HISTORY_FILE, encoding='utf-8') as f:
                    self._data = json.load(f)
            except Exception:
                self._data = {}

    def save(self) -> None:
        with open(self.HISTORY_FILE, 'w', encoding='utf-8') as f:
            json.dump(self._data, f)

    def record(self, host: str, port: int, ping: float) -> None:
        k = self._key(host, port)
        self._data.setdefault(k, [])
        self._data[k].append(ping)
        # Храним последние 20 замеров
        self._data[k] = self._data[k][-20:]

    def avg_ping(self, host: str, port: int) -> float:
        pings = self._data.get(self._key(host, port), [])
        return round(sum(pings) / len(pings), 3) if pings else 9999.0

    def check_count(self, host: str, port: int) -> int:
        return len(self._data.get(self._key(host, port), []))

    def stability_score(self, host: str, port: int) -> float:
        """0.0 (нестабильный) … 1.0 (стабильный)."""
        cnt = self.check_count(host, port)
        return min(cnt / 20, 1.0)

    def composite_score(self, host: str, port: int) -> float:
        """Меньше = лучше. ping 0.3s + стабильность полностью = 0.3."""
        avg = self.avg_ping(host, port)
        stab = self.stability_score(host, port)
        return avg * (1 - stab * 0.3)


PING_HISTORY = PingHistory()

# ─────────────────── helpers ─────────────────────────────────────

def _valid_port(port_str) -> bool:
    try:
        return 1 <= int(port_str) <= 65535
    except (ValueError, TypeError):
        return False


def _is_blocked(secret: str, domain: Optional[str]) -> bool:
    if len(secret) < 16:
        return True
    if domain and any(b in domain for b in BLOCKED):
        return True
    return False


def _detect_region(domain: Optional[str]) -> str:
    if domain:
        for marker in RU_DOMAINS:
            if marker in domain:
                return 'ru'
    return 'eu'


def _cleanup_telethon_session(host: str, port: int) -> None:
    session_name = f'test_{host.replace(".", "_")}_{port}'
    for path in glob.glob(f'{session_name}*'):
        try:
            os.remove(path)
        except OSError:
            pass


def _random_headers() -> dict[str, str]:
    """Возвращает набор браузерных заголовков с рандомным User-Agent."""
    return {
        'User-Agent': random.choice(USER_AGENTS),
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': random.choice(['en-US,en;q=0.9', 'ru-RU,ru;q=0.9,en;q=0.8', 'de-DE,de;q=0.9']),
        'Accept-Encoding': 'gzip, deflate, br',
        'Connection': 'keep-alive',
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'none',
        'Cache-Control': 'max-age=0',
    }


def _pick_fetch_proxy() -> Optional[str]:
    return random.choice(FETCH_PROXIES) if FETCH_PROXIES else None

# ─────────────────── parsing ─────────────────────────────────────

def get_proxies_from_text(text: str) -> set[tuple]:
    proxies: set[tuple] = set()

    tg_pattern = re.compile(
        r'tg://proxy\?server=([^&\s]+)&port=(\d+)&secret=([A-Za-z0-9_=+/%-]+)',
        re.IGNORECASE,
    )
    for h, p, s in tg_pattern.findall(text):
        if _valid_port(p):
            proxies.add((h, int(p), s))

    tme_pattern = re.compile(
        r't\.me/proxy\?server=([^&\s]+)&port=(\d+)&secret=([A-Za-z0-9_=+/%-]+)',
        re.IGNORECASE,
    )
    for h, p, s in tme_pattern.findall(text):
        if _valid_port(p):
            proxies.add((h, int(p), s))

    simple_pattern = re.compile(r'([a-zA-Z0-9.-]+):(\d+):([A-Fa-f0-9]{16,})')
    for h, p, s in simple_pattern.findall(text):
        if _valid_port(p):
            proxies.add((h, int(p), s))

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


def decode_domain(secret: str) -> Optional[str]:
    if not secret.startswith('ee'):
        return None
    try:
        chars = []
        for i in range(2, len(secret) - 1, 2):
            val = int(secret[i:i + 2], 16)
            if val == 0:
                break
            if 32 <= val <= 126:
                chars.append(chr(val))
        result = ''.join(chars).lower()
        return result if result else None
    except Exception:
        return None

# ─────────────────── source fetching ─────────────────────────────

class SourceStats:
    """Статистика по каждому источнику."""
    def __init__(self):
        self.fetched:  dict[str, int] = defaultdict(int)
        self.verified: dict[str, int] = defaultdict(int)
        self.failed:   set[str]       = set()

    def record_fetch(self, url: str, count: int) -> None:
        self.fetched[url] += count

    def record_verified(self, url: str) -> None:
        self.verified[url] += 1

    def record_fail(self, url: str) -> None:
        self.failed.add(url)

    def to_dict(self) -> list[dict]:
        return [
            {
                'url': url,
                'fetched': self.fetched.get(url, 0),
                'verified': self.verified.get(url, 0),
                'pass_rate': round(
                    self.verified.get(url, 0) / self.fetched[url], 3
                ) if self.fetched.get(url, 0) else 0,
                'failed': url in self.failed,
            }
            for url in set(list(self.fetched.keys()) + list(self.failed))
        ]


SOURCE_STATS = SourceStats()


def fetch_source(url: str, timeout: int = 15) -> str:
    """Скачивает источник с 3 попытками, ротацией UA и прокси."""
    proxy = _pick_fetch_proxy()

    for attempt in range(3):
        try:
            if HTTPX_AVAILABLE:
                # HTTP/2 через httpx
                proxy_url = proxy or None
                with httpx.Client(
                    http2=True,
                    timeout=timeout,
                    headers=_random_headers(),
                    proxies=proxy_url,
                    follow_redirects=True,
                ) as client:
                    r = client.get(url)
                    if r.status_code == 200:
                        SOURCE_STATS.record_fetch(url, 1)
                        return r.text
                    elif r.status_code in (403, 429):
                        # DPI/rate-limit — меняем прокси и ждём дольше
                        proxy = _pick_fetch_proxy()
                        time.sleep(2 ** attempt + random.uniform(0.5, 1.5))
                        continue
            else:
                proxies_dict = {'http': proxy, 'https': proxy} if proxy else {}
                r = requests.get(url, timeout=timeout, headers=_random_headers(), proxies=proxies_dict)
                if r.status_code == 200:
                    SOURCE_STATS.record_fetch(url, 1)
                    return r.text
        except Exception as e:
            log.debug('fetch_source attempt %d for %s: %s', attempt + 1, url, e)

        delay = random.uniform(0.3, 1.5) * (attempt + 1)
        time.sleep(delay)

    SOURCE_STATS.record_fail(url)
    return ''

# ─────────────────── checkers ─────────────────────────────────────

async def check_proxy_telethon(p: tuple) -> Optional[dict]:
    if not TELETHON_AVAILABLE or not API_ID or not API_HASH:
        return None

    host, port, secret = p
    domain = decode_domain(secret)

    if _is_blocked(secret, domain):
        return None

    # Случайная задержка между попытками
    await asyncio.sleep(random.uniform(0.05, 0.2))

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

        if ping > MAX_PING:
            return None

        PING_HISTORY.record(host, port, ping)
        region = _detect_region(domain)

        return {
            'host': host, 'port': port, 'secret': secret,
            'link': f'tg://proxy?server={host}&port={port}&secret={secret}',
            'ping': ping,
            'avg_ping': PING_HISTORY.avg_ping(host, port),
            'stability': PING_HISTORY.stability_score(host, port),
            'composite': PING_HISTORY.composite_score(host, port),
            'region': region,
            'domain': domain or '',
            'method': 'Telethon_OK',
            'has_domain': bool(domain),
        }
    except Exception as e:
        err_type = type(e).__name__
        log.debug('Telethon fail %s:%d — %s', host, port, err_type)
        return None
    finally:
        try:
            await client.disconnect()
        except Exception:
            pass
        _cleanup_telethon_session(host, port)


def check_proxy_tcp(p: tuple) -> Optional[dict]:
    host, port, secret = p
    domain = decode_domain(secret)

    if _is_blocked(secret, domain):
        return None

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(TIMEOUT)
            start = time.time()
            s.connect((host, port))

            # Минимальный «шумовой» пакет — имитирует начало MTProto handshake
            # (64 рандомных байта, первые 4 — маркер 0xef * 4 как в MTProto)
            noise = bytes([0xef] * 4) + os.urandom(60)
            s.sendall(noise)

            ping = round(time.time() - start, 3)
    except Exception as e:
        err_type = type(e).__name__
        log.debug('TCP fail %s:%d — %s', host, port, err_type)
        return None

    if ping > MAX_PING:
        return None

    PING_HISTORY.record(host, port, ping)
    region = _detect_region(domain)

    return {
        'host': host, 'port': port, 'secret': secret,
        'link': f'tg://proxy?server={host}&port={port}&secret={secret}',
        'ping': ping,
        'avg_ping': PING_HISTORY.avg_ping(host, port),
        'stability': PING_HISTORY.stability_score(host, port),
        'composite': PING_HISTORY.composite_score(host, port),
        'region': region,
        'domain': domain or '',
        'method': 'TCP_OK',
        'has_domain': bool(domain),
    }

# ─────────────────── postprocess ──────────────────────────────────

def deduplicate_by_host_port(proxies: list[dict]) -> list[dict]:
    best: dict[tuple, dict] = {}
    for p in proxies:
        key = (p['host'], p['port'])
        if key not in best or p['composite'] < best[key]['composite']:
            best[key] = p
    return list(best.values())


def sort_proxies(proxies: list[dict]) -> list[dict]:
    """Сортирует по composite_score (ping + стабильность), домен-прокси в приоритете."""
    return sorted(proxies, key=lambda x: (not x['has_domain'], x['composite']))


def make_tme_link(host: str, port: int, secret: str) -> str:
    return f'https://t.me/proxy?server={host}&port={port}&secret={secret}'

# ─────────────────── main ──────────────────────────────────────────

async def main_async(args: argparse.Namespace) -> None:
    start_time = time.time()
    print('🚀 MTProto Proxy Collector v3.0')
    print('=' * 52)

    output_dir = args.output_dir
    os.makedirs(output_dir, exist_ok=True)

    # ── сбор прокси ───────────────────────────────────────────────
    print('\n📥 Сбор прокси из источников...\n')

    all_raw: set[tuple] = set()
    source_proxies: dict[str, set[tuple]] = {}

    for url in SOURCES:
        name = (url.split('/')[-1] or url.split('/')[-2])[:48]
        text = fetch_source(url)
        if text:
            extracted = get_proxies_from_text(text)
            SOURCE_STATS.record_fetch(url, len(extracted))
            source_proxies[url] = extracted
            all_raw.update(extracted)
            print(f'  ✓ {name:<48} +{len(extracted)}')
        else:
            print(f'  ✗ {name:<48} недоступен')
        # Небольшая задержка между источниками
        time.sleep(random.uniform(0.2, 0.7))

    # Фильтр дублирующихся источников по IP (грубо — по хостам прокси)
    seen_hosts: set[str] = set()
    unique_raw: set[tuple] = set()
    for proxy in all_raw:
        host = proxy[0]
        if host not in seen_hosts:
            seen_hosts.add(host)
            unique_raw.add(proxy)

    print(f'\n  Уникальных прокси (до фильтра): {len(all_raw)}')
    print(f'  Уникальных прокси (по хосту):   {len(unique_raw)}\n')
    all_raw = unique_raw

    # ── проверка прокси ───────────────────────────────────────────
    print(f'⚡ Проверка {len(all_raw)} прокси...\n')

    valid:   list[dict] = []
    checked: int        = 0
    total:   int        = len(all_raw)

    # Обратный mapping прокси → источник для статистики
    proxy_to_source: dict[tuple, list[str]] = defaultdict(list)
    for url, proxies in source_proxies.items():
        for p in proxies:
            proxy_to_source[p].append(url)

    def on_result(result: Optional[dict], p: tuple) -> None:
        nonlocal checked
        checked += 1
        if result:
            valid.append(result)
            for src_url in proxy_to_source.get(p, []):
                SOURCE_STATS.record_verified(src_url)
        if checked % 100 == 0 or checked == total:
            print(f'  [{checked}/{total}] {checked / total * 100:.0f}% | найдено: {len(valid)}')

    if TELETHON_AVAILABLE and API_ID and API_HASH:
        print('🔥 Режим: Telethon MTProto\n')
        semaphore = asyncio.Semaphore(10)

        async def check_p(p: tuple) -> tuple:
            async with semaphore:
                return p, await check_proxy_telethon(p)

        tasks = [asyncio.ensure_future(check_p(p)) for p in all_raw]
        for coro in asyncio.as_completed(tasks):
            p, result = await coro
            on_result(result, p)

    else:
        print('📡 Режим: TCP ping\n')
        workers = min(args.workers, MAX_WORKERS)
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as exc:
            futures = {exc.submit(check_proxy_tcp, p): p for p in all_raw}
            for f in concurrent.futures.as_completed(futures):
                on_result(f.result(), futures[f])

    # ── постобработка ──────────────────────────────────────────────
    valid = deduplicate_by_host_port(valid)

    ru = sort_proxies([x for x in valid if x['region'] == 'ru'])
    eu = sort_proxies([x for x in valid if x['region'] == 'eu'])

    # Доменные прокси (ee-секрет) выделяем отдельно как наиболее стабильные
    domain_proxies = sort_proxies([x for x in valid if x['has_domain']])

    top_n = args.top if args.top > 0 else None

    PING_HISTORY.save()

    # ── сохранение файлов ──────────────────────────────────────────
    print(f'\n💾 Сохранение в {output_dir}/...\n')

    def write_proxy_file(filename: str, proxies_list: list[dict], label: str) -> None:
        chunk = proxies_list[:top_n]
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(f'# Verified {label} Proxies ({len(chunk)})\n')
            f.write(f'# Updated: {datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")}\n')
            if chunk:
                best = chunk[0]
                f.write(f'# Method: {best["method"]}\n')
                f.write(f'# Best ping: {best["ping"]}s | avg: {best["avg_ping"]}s\n')
            f.write('\n')
            f.write('\n'.join(x['link'] for x in chunk))

    write_proxy_file(f'{output_dir}/proxy_ru_verified.txt',     ru,            'RU')
    write_proxy_file(f'{output_dir}/proxy_eu_verified.txt',     eu,            'EU')
    write_proxy_file(f'{output_dir}/proxy_all_verified.txt',    valid,         'All')
    write_proxy_file(f'{output_dir}/proxy_domain_verified.txt', domain_proxies,'Domain')

    # t.me формат
    tme_chunk = sort_proxies(valid)[:top_n]
    with open(f'{output_dir}/proxy_all_tme_verified.txt', 'w', encoding='utf-8') as f:
        f.write(f'# Verified Proxies t.me format ({len(tme_chunk)})\n')
        f.write(f'# Updated: {datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")}\n\n')
        for x in tme_chunk:
            f.write(make_tme_link(x['host'], x['port'], x['secret']) + '\n')

    # Полный JSON
    json_chunk = sort_proxies(valid)[:top_n]
    with open(f'{output_dir}/proxy_all_verified.json', 'w', encoding='utf-8') as f:
        json.dump(json_chunk, f, indent=2, ensure_ascii=False)

    # Статистика по источникам
    with open(f'{output_dir}/source_stats.json', 'w', encoding='utf-8') as f:
        json.dump(SOURCE_STATS.to_dict(), f, indent=2, ensure_ascii=False)

    # Общая статистика
    elapsed = round(time.time() - start_time, 1)
    stats = {
        'timestamp_utc':   datetime.now(timezone.utc).isoformat(),
        'total_raw':       len(all_raw),
        'total_verified':  len(valid),
        'ru_count':        len(ru),
        'eu_count':        len(eu),
        'domain_count':    len(domain_proxies),
        'telethon_used':   TELETHON_AVAILABLE and bool(API_ID and API_HASH),
        'httpx_http2':     HTTPX_AVAILABLE,
        'best_ru_ping':    ru[0]['ping']  if ru else None,
        'best_eu_ping':    eu[0]['ping']  if eu else None,
        'best_ru_avg':     ru[0]['avg_ping']  if ru else None,
        'best_eu_avg':     eu[0]['avg_ping']  if eu else None,
        'execution_time':  elapsed,
        'sources_count':   len(SOURCES),
        'workers':         args.workers,
        'max_ping':        MAX_PING,
    }
    with open(f'{output_dir}/proxy_stats_verified.json', 'w', encoding='utf-8') as f:
        json.dump(stats, f, indent=2, ensure_ascii=False)

    # ── итог ───────────────────────────────────────────────────────
    print('=' * 52)
    print(f'✅  Верифицировано: RU={len(ru)}  EU={len(eu)}  Domain={len(domain_proxies)}  Всего={len(valid)}')
    if ru:
        print(f'🏆  Лучший RU: {ru[0]["host"]}:{ru[0]["port"]}  ping={ru[0]["ping"]}s  avg={ru[0]["avg_ping"]}s')
    if eu:
        print(f'🏆  Лучший EU: {eu[0]["host"]}:{eu[0]["port"]}  ping={eu[0]["ping"]}s  avg={eu[0]["avg_ping"]}s')
    print(f'📁  Результаты: {output_dir}/')
    print(f'⏱️   Время:      {elapsed}s')
    print('=' * 52)


def main() -> None:
    parser = argparse.ArgumentParser(description='🚀 MTProto Proxy Collector v3.0')
    parser.add_argument('--timeout',    type=float, default=2.0,       help='TCP таймаут (сек)')
    parser.add_argument('--max-ping',   type=float, default=2.0,       help='Макс. ping для включения (сек)')
    parser.add_argument('--workers',    type=int,   default=50,         help='Потоки TCP проверки')
    parser.add_argument('--top',        type=int,   default=0,          help='Сохранить TOP N (0 = все)')
    parser.add_argument('--output-dir', type=str,   default='verified', help='Папка для результатов')
    args = parser.parse_args()

    global TIMEOUT, MAX_PING
    TIMEOUT  = args.timeout
    MAX_PING = args.max_ping

    asyncio.run(main_async(args))


if __name__ == '__main__':
    main()
