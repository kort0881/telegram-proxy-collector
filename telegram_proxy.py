"""Check that a proxy relays Telegram's unauthenticated MTProto handshake."""

import base64
import hashlib
import hmac
import os
import socket
import struct
import time
from dataclasses import dataclass
from urllib.parse import unquote

from telethon.crypto import AESModeCTR
from telethon.extensions import BinaryReader
from telethon.tl.functions import ReqPqMultiRequest
from telethon.tl.types import ResPQ


# Production DC 2 bootstrap address from Telegram Desktop.
_DC_ID = 2
_DC_ADDRESS = socket.inet_aton('149.154.167.51')
_DC_PORT = 443
_INTERMEDIATE = b'\xee' * 4
_PADDED_INTERMEDIATE = b'\xdd' * 4
_CHANGE_CIPHER_SPEC = b'\x14\x03\x03\x00\x01\x01'


@dataclass(frozen=True)
class MTProxySecret:
    key: bytes
    padded: bool = False
    domain: str = ''

    @classmethod
    def parse(cls, value: str) -> 'MTProxySecret':
        value = unquote(value)
        try:
            decoded = bytes.fromhex(value)
            if len(decoded) < 16:
                raise ValueError('Too short for a hexadecimal secret')
        except ValueError:
            decoded = base64.b64decode(value + '=' * (-len(value) % 4), altchars=b'-_', validate=True)

        if len(decoded) == 16:
            return cls(decoded)
        if len(decoded) == 17 and decoded[0] == 0xdd:
            return cls(decoded[1:], padded=True)
        if 17 < len(decoded) <= 270 and decoded[0] == 0xee:
            domain = decoded[17:].decode('ascii').lower()
            if all(char.isalnum() or char in '.-' for char in domain):
                return cls(decoded[1:17], padded=True, domain=domain)
        raise ValueError('Invalid MTProxy secret')


def _remaining(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError('Telegram proxy check timed out')
    return remaining


class _SocketStream:
    def __init__(self, sock: socket.socket, deadline: float):
        self.sock = sock
        self.deadline = deadline

    def read(self, size: int) -> bytes:
        data = bytearray()
        while len(data) < size:
            self.sock.settimeout(_remaining(self.deadline))
            chunk = self.sock.recv(size - len(data))
            if not chunk:
                raise ConnectionError('Proxy closed the connection')
            data.extend(chunk)
        return bytes(data)

    def write(self, data: bytes) -> None:
        self.sock.settimeout(_remaining(self.deadline))
        self.sock.sendall(data)


def _tls_extension(kind: int, data: bytes) -> bytes:
    return struct.pack('!HH', kind, len(data)) + data


def _tls_record(kind: int, data: bytes, version: int = 0x0303) -> bytes:
    return struct.pack('!BHH', kind, version, len(data)) + data


def _fake_tls_hello(secret: MTProxySecret) -> bytes:
    # TDLib puts an HMAC and the timestamp in the ClientHello random field.
    domain = secret.domain.encode('ascii')
    sni = struct.pack('!HBH', len(domain) + 3, 0, len(domain)) + domain
    extensions = b''.join((
        _tls_extension(0, sni),
        _tls_extension(10, b'\x00\x04\x00\x1d\x00\x17'),  # Supported groups
        _tls_extension(13, b'\x00\x06\x04\x03\x08\x04\x04\x01'),  # Signature algorithms
        _tls_extension(43, b'\x04\x03\x04\x03\x03'),  # Supported versions
        _tls_extension(51, b'\x00\x24\x00\x1d\x00\x20' + os.urandom(32)),  # X25519 key share
    ))
    ciphers = b'\x13\x01\x13\x02\x13\x03\xc0\x2f'
    body = b'\x03\x03' + bytes(32) + b'\x20' + os.urandom(32)
    body += struct.pack('!H', len(ciphers)) + ciphers + b'\x01\x00'
    # Pad the ClientHello so it also works with servers expecting a 512-byte record body.
    padding = 512 - 4 - len(body) - 2 - len(extensions) - 4
    extensions += _tls_extension(21, bytes(padding))
    body += struct.pack('!H', len(extensions)) + extensions
    hello = _tls_record(0x16, b'\x01' + len(body).to_bytes(3, 'big') + body, version=0x0301)
    digest = hmac.digest(secret.key, hello, 'sha256')
    timestamp = int(time.time()).to_bytes(4, 'little')
    signed_random = digest[:28] + bytes(a ^ b for a, b in zip(digest[28:], timestamp))
    return hello[:11] + signed_random + hello[43:]


class _FakeTLSStream:
    def __init__(self, stream: _SocketStream, secret: MTProxySecret):
        self.stream = stream
        self.buffer = bytearray()
        hello = _fake_tls_hello(secret)
        stream.write(hello)
        server_hello = self._read_record(0x16)
        if len(server_hello) < 43 or server_hello[5] != 2:
            raise ConnectionError('Invalid FakeTLS ServerHello')
        ccs = self._read_record(0x14)
        if ccs != _CHANGE_CIPHER_SPEC:
            raise ConnectionError('Invalid FakeTLS ChangeCipherSpec')
        response = server_hello + ccs + self._read_record(0x17)
        expected = hmac.digest(secret.key, hello[11:43] + response[:11] + bytes(32) + response[43:], 'sha256')
        if not hmac.compare_digest(response[11:43], expected):
            raise ConnectionError('Invalid FakeTLS server HMAC')

    def _read_record(self, kind: int) -> bytes:
        header = self.stream.read(5)
        record_type, version, size = struct.unpack('!BHH', header)
        if record_type != kind or version != 0x0303 or not 0 < size <= 18432:
            raise ConnectionError('Unexpected FakeTLS record')
        return header + self.stream.read(size)

    def read(self, size: int) -> bytes:
        while len(self.buffer) < size:
            self.buffer.extend(self._read_record(0x17)[5:])
        data = bytes(self.buffer[:size])
        del self.buffer[:size]
        return data

    def write(self, data: bytes) -> None:
        # The probe writes a single MTProto request after the FakeTLS handshake.
        self.stream.write(_CHANGE_CIPHER_SPEC + _tls_record(0x17, data))


def _socks5_connect(stream: _SocketStream, username: str | None, password: str | None) -> None:
    user = (username or '').encode('utf-8')
    passwd = (password or '').encode('utf-8')
    has_auth = 0 < len(user) <= 255 and 0 < len(passwd) <= 255
    stream.write(b'\x05\x02\x00\x02' if has_auth else b'\x05\x01\x00')
    method = stream.read(2)
    if method == b'\x05\x02' and has_auth:
        stream.write(b'\x01' + bytes([len(user)]) + user + bytes([len(passwd)]) + passwd)
        if stream.read(2) != b'\x01\x00':
            raise ConnectionError('SOCKS5 authentication failed')
    elif method != b'\x05\x00':
        raise ConnectionError('SOCKS5 rejected the offered authentication methods')

    stream.write(b'\x05\x01\x00\x01' + _DC_ADDRESS + struct.pack('!H', _DC_PORT))
    version, status, reserved, address_type = stream.read(4)
    if (version, status, reserved) != (5, 0, 0):
        raise ConnectionError('SOCKS5 could not connect to Telegram')
    if address_type == 1:
        address_size = 4
    elif address_type == 4:
        address_size = 16
    elif address_type == 3:
        address_size = stream.read(1)[0]
    else:
        raise ConnectionError('Invalid SOCKS5 address type')
    stream.read(address_size + 2)  # Consume the bound address and port before MTProto starts.


def _obfuscated_header(secret: MTProxySecret) -> tuple[bytes, AESModeCTR, AESModeCTR]:
    forbidden = (b'HEAD', b'POST', b'GET ', b'OPTI', b'\x16\x03\x01\x02', _INTERMEDIATE, _PADDED_INTERMEDIATE)
    header = os.urandom(64)
    while header[0] == 0xef or header[:4] in forbidden or header[4:8] == bytes(4):
        header = os.urandom(64)
    forward = header[8:56]
    reverse = forward[::-1]
    encryptor = AESModeCTR(hashlib.sha256(forward[:32] + secret.key).digest(), forward[32:])
    decryptor = AESModeCTR(hashlib.sha256(reverse[:32] + secret.key).digest(), reverse[32:])
    marker = _PADDED_INTERMEDIATE if secret.padded else _INTERMEDIATE
    header = header[:56] + marker + struct.pack('<h', _DC_ID) + header[62:]
    return header[:56] + encryptor.encrypt(header)[56:], encryptor, decryptor


def _valid_res_pq(packet: bytes, nonce: int, padded: bool) -> bool:
    auth_key_id, msg_id, length = struct.unpack_from('<QQI', packet)
    padding_size = len(packet) - 20 - length
    if auth_key_id != 0 or not msg_id or length % 4 or not 0 <= padding_size <= (15 if padded else 0):
        return False

    body = BinaryReader(packet[20:20 + length])
    if body.read_int(signed=False) != ResPQ.CONSTRUCTOR_ID or body.read_large_int(128) != nonce:
        return False
    body.read(16)  # Server nonce.
    pq = body.tgread_bytes()
    if not 0 < len(pq) <= 8 or body.read_int(signed=False) != 0x1cb5c415:
        return False
    count = body.read_int()
    return count > 0 and len(body.read()) == 8 * count


def check_telegram_proxy(
    host: str,
    port: int,
    timeout: float,
    *,
    secret: MTProxySecret | None = None,
    credentials: tuple[str | None, str | None] = (None, None),
) -> bool:
    """Open the second connection and require a matching resPQ through the proxy."""
    deadline = time.monotonic() + timeout
    try:
        with socket.create_connection((host, port), timeout=_remaining(deadline)) as sock:
            stream: _SocketStream | _FakeTLSStream = _SocketStream(sock, deadline)
            if secret is None:
                _socks5_connect(stream, *credentials)
                header = _INTERMEDIATE
            else:
                if secret.domain:
                    stream = _FakeTLSStream(stream, secret)
                header, encryptor, decryptor = _obfuscated_header(secret)

            nonce = int.from_bytes(os.urandom(16), 'little', signed=True)
            request = bytes(ReqPqMultiRequest(nonce))
            msg_id = (time.time_ns() * (1 << 32) // 1_000_000_000) & ~3
            payload = struct.pack('<QQI', 0, msg_id, len(request)) + request
            padded = secret is not None and secret.padded
            if padded:
                payload += os.urandom(os.urandom(1)[0] % 16)
            packet = struct.pack('<I', len(payload)) + payload
            stream.write(header + (encryptor.encrypt(packet) if secret is not None else packet))

            length = stream.read(4)
            if secret is not None:
                length = decryptor.decrypt(length)
            size, = struct.unpack('<I', length)
            if not 20 <= size <= 1024:
                return False
            response = stream.read(size)
            if secret is not None:
                response = decryptor.decrypt(response)
            return _valid_res_pq(response, nonce, padded)
    except (OSError, ValueError, BufferError, struct.error):
        return False
