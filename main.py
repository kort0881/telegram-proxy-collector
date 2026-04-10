"""
MTProto Proxy Collector v3.0
Улучшения: ping-история, рейтинг стабильности, статистика по источникам, Tor/прокси-пул.
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


# Всегда используем только requests; если хочешь httpx — включи его вручную
HTTPX_AVAILABLE = False
try:
    import httpx
    HTTPX_AVAILABLE = True
except ImportError:
    import requests

try:
    from telethon import TelegramClient
    from telethon.connection import ConnectionTcpMTProxyRandomizedIntermediate
    TELETHON_AVAILABLE = True
except ImportError:
    TELETHON_AVAILABLE = False

# ─────────────────── конфигурация ───────────────────────────────

# Telegram API для Telethon (если нужен полноценный MTProto-тест)
API_ID   = None  # my.telegram.org
API_HASH = None

# Список User-Agent реальных браузеров (упрощённый)
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
]

SOURCES = [
    "https://raw.githubusercontent.com/SoliSpirit/mtproto/master/all_proxies.txt",
    "https://raw.githubusercontent.com/Grim1313/mtproto-for-telegram/refs/heads/master/all_proxies.txt",
    "https://raw.githubusercontent.com/ALIILAPRO/MTProtoProxy/main/mtproto.txt",
    "https://raw.githubusercontent.com/yemixzy/proxy-projects/main/proxies/mtproto.txt",
    "https://mtpro.xyz/api/?type=mtproto",
    "https://mtpro.xyz/api/?type=mtproto-ru",
]

# Включаешь Tor/SOCKS5 — так новые источники почти точно заработают
FETCH_PROXIES: list[str] = [
    "socks5h://127.0.0.1:9050",  # Tor — включи и запусти `sudo systemctl start tor`
    # "http://user:pass@proxy.example.com:8080",
]

TIMEOUT     = 2.0
MAX_WORKERS = 50          # уменьшено под DPI
MAX_PING    = 2.0         # прокси с ping > MAX_PING не берём
MIN_CHECKS_FOR_STABLE = 2 # сколько проверок нужно для статуса «стабильный»

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

def _valid_port(port_str: str) -> bool:
    try:
        return 1 <= int(port_str) <= 65535
    except (ValueError, TypeError):
        return False


def _is_blocked(secret: str, domain: str | None) -> bool:
    if len(secret) < 16:
        return True
    if domain and any(b in domain for b in BLOCKED):
        return True
    return False


def _detect_region(domain: str | None) -> str:
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
    """Минимальные, «незаметные» заголовки, как в старом коде."""
    return {
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": "*/*",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
    }


def _pick_fetch_proxy() -> Optional[str]:
    return random.choice(FETCH_PROXIES) if FETCH_PROXIES else None

# ─────────────────── parsing ─────────────────────────────────────

def get_proxies_from_text(text: str) -> set[tuple]:
    proxies: set[tuple] = set()

    tg_pattern = re.compile(
        r'tg://proxy\\?server=([^&\\s]+)&port=(\\d+)&secret=([A-Za-z0-9_=+/%-]+)',
        re.IGNORECASE,
    )
    for h, p, s in tg_pattern.findall(text):
        if _valid_port(p):
            proxies.add((h, int(p), s))

    tme_pattern = re.compile(
        r't\\.me/proxy\\?server=([^&\\s]+)&port=(\\d+)&secret=([A-Za-z0-9_=+/%-]+)',
        re.IGNORECASE,
    )
    for h, p, s in tme_pattern.findall(text):
        if _valid_port(p):
            proxies.add((h, int(p), s))

    simple_pattern = re.compile(r'([a-zA-Z0-9.-]+):(\\d+):([A-Fa-f0-9]{16,})')
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


def decode_domain(secret: str) -> str | None:
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
    """Скачивает источник с 3 попытками через requests (Tor/прокси при наличии)."""
    proxy = _pick_fetch_proxy()

    for attempt in range(3):
        try:
            # Всегда стучим через requests + прокси
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

    # Лёгкая задержка между запросами для обхода DPI
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

            # Минимальный «шумовой» пакет под MTProto
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
        # Лёгкая задержка между источниками
        time.sleep(random.uniform(0.2, 0.7))

    # Грубая фильтрация по уникальным х
