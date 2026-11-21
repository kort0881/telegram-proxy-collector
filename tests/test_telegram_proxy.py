import base64
import hashlib
import hmac
import json
import socket
import struct
from argparse import Namespace
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import main
from telegram_proxy import MTProxySecret, check_telegram_proxy
from telethon.crypto import AESModeCTR


KEY = bytes.fromhex('0123456789abcdef0123456789abcdef')
CCS = b'\x14\x03\x03\x00\x01\x01'


def _record(kind, payload):
    return struct.pack('!BHH', kind, 0x0303, len(payload)) + payload


def _read_record(reader, kind, version=0x0303):
    received_kind, received_version, size = struct.unpack('!BHH', reader.read(5))
    assert (received_kind, received_version) == (kind, version)
    return reader.read(size)


def _reply(packet, *, bad_nonce=False, padding=b''):
    auth_id, msg_id, length, constructor = struct.unpack_from('<QQII', packet)
    assert auth_id == 0 and msg_id % 4 == 0 and length == 20
    assert constructor == 0xbe7e8ef1
    nonce = bytes(16) if bad_nonce else packet[24:40]
    pq = b'\x08\x01\x23\x45\x67\x89\xab\xcd\xef\0\0\0'
    res_pq = struct.pack('<I', 0x05162463) + nonce + b'S' * 16 + pq
    res_pq += struct.pack('<IIQ', 0x1cb5c415, 1, 42)
    payload = struct.pack('<QQI', 0, msg_id + 1, len(res_pq)) + res_pq + padding
    return struct.pack('<I', len(payload)) + payload


def _mtproxy_server(sock, secret, *, bad_nonce=False, bad_digest=False):
    with sock.makefile('rb') as reader:
        if secret.domain:
            hello = _read_record(reader, 0x16, version=0x0301)
            assert len(hello) == 512 and secret.domain.encode() in hello
            server_hello = _record(0x16, b'\x02\0\0\x22\x03\x03' + bytes(32))
            handshake = server_hello + CCS + _record(0x17, b'fake certificate')
            digest = hmac.digest(secret.key, hello[6:38] + handshake, 'sha256')
            handshake = handshake[:11] + (bytes(32) if bad_digest else digest) + handshake[43:]
            sock.sendall(handshake)
            if bad_digest:
                assert reader.read(1) == b''
                return
            assert reader.read(len(CCS)) == CCS
            incoming = _read_record(reader, 0x17)
            header, encrypted = incoming[:64], incoming[64:]
        else:
            header = reader.read(64)

        forward = header[8:56]
        reverse = forward[::-1]
        decoder = AESModeCTR(hashlib.sha256(forward[:32] + KEY).digest(), forward[32:])
        encoder = AESModeCTR(hashlib.sha256(reverse[:32] + KEY).digest(), reverse[32:])
        marker = b'\xdd' if secret.padded else b'\xee'
        assert decoder.decrypt(header)[56:62] == marker * 4 + b'\x02\0'
        if secret.domain:
            clear = decoder.decrypt(encrypted)
            assert int.from_bytes(clear[:4], 'little') == len(clear) - 4
            request = clear[4:]
        else:
            size = int.from_bytes(decoder.decrypt(reader.read(4)), 'little')
            request = decoder.decrypt(reader.read(size))
        response = encoder.encrypt(_reply(request, bad_nonce=bad_nonce, padding=b'12345' if secret.padded else b''))
        if secret.domain:
            # The transport must assemble MTProto frames split across TLS records.
            response = _record(0x17, response[:2]) + _record(0x17, response[2:])
        sock.sendall(response)


def _socks_server(sock, *, authenticated, allow_connect):
    with sock.makefile('rb') as reader:
        if authenticated:
            assert reader.read(4) == b'\x05\x02\0\x02'
            sock.sendall(b'\x05\x02')
            assert reader.read(7) == b'\x01\x02u@\x02p!'
            sock.sendall(b'\x01\0')
        else:
            assert reader.read(3) == b'\x05\x01\0'
            sock.sendall(b'\x05\0')
        assert reader.read(10) == b'\x05\x01\0\x01' + socket.inet_aton('149.154.167.51') + b'\x01\xbb'
        status = 0 if allow_connect else 5
        sock.sendall(bytes([5, status, 0, 3, 3]) + b'abc\0\0')
        if allow_connect:
            assert reader.read(4) == b'\xee' * 4
            size = int.from_bytes(reader.read(4), 'little')
            sock.sendall(_reply(reader.read(size)))


def _probe(server, **kwargs):
    with ThreadPoolExecutor(max_workers=1) as pool:
        client, peer = socket.socketpair()
        with client, peer:
            peer.settimeout(2)
            task = pool.submit(server, peer)
            with patch('telegram_proxy.socket.create_connection', return_value=client):
                result = check_telegram_proxy('proxy.example', 443, 2, **kwargs)
            task.result()
            return result


def test_mtproto_supports_plain_padded_and_faketls():
    for raw in (KEY, b'\xdd' + KEY, b'\xee' + KEY + b'example.com'):
        encoded = base64.urlsafe_b64encode(raw).decode().rstrip('=')
        secret = MTProxySecret.parse(encoded)
        assert secret == MTProxySecret.parse(raw.hex())
        assert _probe(lambda sock: _mtproxy_server(sock, secret), secret=secret)


def test_mtproto_rejects_wrong_nonce_and_fake_tls_digest():
    plain = MTProxySecret(KEY)
    tls = MTProxySecret(KEY, padded=True, domain='example.com')
    assert not _probe(lambda sock: _mtproxy_server(sock, plain, bad_nonce=True), secret=plain)
    assert not _probe(lambda sock: _mtproxy_server(sock, tls, bad_digest=True), secret=tls)


def test_socks5_requires_connect_to_telegram_and_supports_authentication():
    assert _probe(lambda sock: _socks_server(sock, authenticated=False, allow_connect=True))
    assert not _probe(lambda sock: _socks_server(sock, authenticated=False, allow_connect=False))
    assert _probe(lambda sock: _socks_server(sock, authenticated=True, allow_connect=True), credentials=('u@', 'p!'))


def test_collector_requires_protocol_check_after_tcp_ping():
    proxy, = main.get_proxies_from_text('tg://socks?server=proxy.example&port=1080&user=u%40&pass=p%21')
    with patch('main.socket.create_connection', side_effect=TimeoutError), patch('main.check_telegram_proxy') as check:
        assert main.check_proxy_tcp(proxy, 2) is None
        check.assert_not_called()
    with patch('main.socket.create_connection'), patch('main.check_telegram_proxy', side_effect=[False, True]) as check:
        assert main.check_proxy_tcp(proxy, 2) is None
        result = main.check_proxy_tcp(proxy, 2)
        assert result['method'] == 'TELEGRAM_OK'
        assert result['link'] == 'tg://socks?server=proxy.example&port=1080&user=u%40&pass=p%21'
        check.assert_called_with('proxy.example', 1080, 2, secret=None, credentials=('u@', 'p!'))


def test_seen_cache_requires_telegram_verification_method():
    entry = ('mtproto', 'proxy.example', 443, KEY.hex())
    with TemporaryDirectory() as tmp:
        path = Path(tmp) / 'seen.json'
        main.save_seen(str(path), {entry})
        assert main.load_seen(str(path)) == {entry}
        data = json.loads(path.read_text())
        del data['method']
        path.write_text(json.dumps(data))
        assert main.load_seen(str(path)) == set()


def test_run_replaces_previous_list_when_no_proxy_passes():
    hosts = ('good.example', 'bad.example')
    links = [f'tg://proxy?server={host}&port=443&secret={KEY.hex()}' for host in hosts]
    with TemporaryDirectory() as tmp:
        output = Path(tmp) / 'verified'
        args = Namespace(geoip=None, output_dir=str(output), manual=None, seen_file=None,
                         seen_ttl=0, max_check=0, dry_run=False, workers=1, timeout=2, top=0)
        with patch.multiple(main, SOURCES=[], SOCKS_SOURCES=[], MANUAL_PROXIES=links,
                            HISTORY_FILE=str(Path(tmp) / 'history.json')), patch('main.socket.create_connection'):
            for passing_hosts in ({hosts[0]}, set()):
                with patch('main.check_telegram_proxy', side_effect=lambda host, *a, **kw: host in passing_hosts):
                    main.run(args)
                records = json.loads((output / 'proxy_all_verified.json').read_text())
                assert {record['host'] for record in records} == passing_hosts
                assert all(record['method'] == 'TELEGRAM_OK' for record in records)
                saved = (output / 'proxy_all.txt').read_text().splitlines()
                assert [line for line in saved if line.startswith('tg://')] == (links[:1] if passing_hosts else [])
