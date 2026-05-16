import socket as _socket
import urllib.request
import http.client

import random
from collections import Counter
from typing import Dict, Iterator, List, Optional
from urllib.request import Request


ZERO_64 = b'\x00' * 64
HANDSHAKE_LEN = 64
SKIP_LEN = 8
PREKEY_LEN = 32
KEY_LEN = 32
IV_LEN = 16
PROTO_TAG_POS = 56
DC_IDX_POS = 60

PROTO_TAG_ABRIDGED = b'\xef\xef\xef\xef'
PROTO_TAG_INTERMEDIATE = b'\xee\xee\xee\xee'
PROTO_TAG_SECURE = b'\xdd\xdd\xdd\xdd'

PROTO_ABRIDGED_INT = 0xEFEFEFEF
PROTO_INTERMEDIATE_INT = 0xEEEEEEEE
PROTO_PADDED_INTERMEDIATE_INT = 0xDDDDDDDD

RESERVED_FIRST_BYTES = {0xEF}
RESERVED_STARTS = {b'\x48\x45\x41\x44', b'\x50\x4F\x53\x54',
                    b'\x47\x45\x54\x20', b'\xee\xee\xee\xee',
                    b'\xdd\xdd\xdd\xdd', b'\x16\x03\x01\x02'}
RESERVED_CONTINUE = b'\x00\x00\x00\x00'

_GITHUB_IPS: Dict[str, str] = {
    "release-assets.githubusercontent.com": "185.199.109.133",
    "raw.githubusercontent.com": "185.199.109.133",
}


def human_bytes(n: int) -> str:
    for unit in ('B', 'KB', 'MB', 'GB'):
        if abs(n) < 1024:
            return f"{n:.1f}{unit}"
        n /= 1024  # type: ignore
    return f"{n:.1f}TB"


class _Stats:
    def __init__(self):
        self.connections_total = 0
        self.connections_active = 0
        self.connections_ws = 0
        self.connections_tcp_fallback = 0
        self.connections_cfproxy = 0
        self.connections_bad = 0
        self.connections_masked = 0
        self.ws_errors = 0
        self.bytes_up = 0
        self.bytes_down = 0
        self.pool_hits = 0
        self.pool_misses = 0

    def summary(self) -> str:
        pool_total = self.pool_hits + self.pool_misses
        pool_s = f"{self.pool_hits}/{pool_total}" if pool_total else "n/a"
        return (
            f"total={self.connections_total} "
            f"active={self.connections_active} "
            f"ws={self.connections_ws} "
            f"tcp_fb={self.connections_tcp_fallback} "
            f"cf={self.connections_cfproxy} "
            f"bad={self.connections_bad} "
            f"masked={self.connections_masked} "
            f"err={self.ws_errors} "
            f"pool={pool_s} "
            f"up={human_bytes(self.bytes_up)} "
            f"down={human_bytes(self.bytes_down)}"
        )


stats = _Stats()


class _Balancer:
    def __init__(self):
        self.domains: List[str] = []
        self._dc_to_domain: Dict[int, str] = {}

    def update_domains_list(self, domains_list: List[str]) -> None:
        if Counter(self.domains) == Counter(domains_list):
            return

        self.domains = domains_list[:]
        self._dc_to_domain = {
            dc_id: random.choice(self.domains)
            for dc_id in (1, 2, 3, 4, 5, 203)
        }

    def update_domain_for_dc(self, dc_id: int, domain: str) -> bool:
        if self._dc_to_domain.get(dc_id) == domain:
            return False

        self._dc_to_domain[dc_id] = domain
        return True

    def get_domains_for_dc(self, dc_id: int) -> Iterator[str]:
        current_domain = self._dc_to_domain.get(dc_id)
        if current_domain is not None:
            yield current_domain

        shuffled_domains = self.domains[:]
        random.shuffle(shuffled_domains)

        for domain in shuffled_domains:
            if domain != current_domain:
                yield domain


balancer = _Balancer()


def get_link_host(host: str) -> Optional[str]:
    if host == '0.0.0.0':
        try:
            with _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM) as _s:
                _s.connect(('8.8.8.8', 80))
                link_host = _s.getsockname()[0]
        except OSError:
            link_host = '127.0.0.1'
        return link_host
    else:
        return host


class _PinnedHTTPSHandler(urllib.request.HTTPSHandler):
    def https_open(self, req: Request):
        host = req.host.split(":")[0]
        ip = _GITHUB_IPS.get(host)
        if not ip:
            return super().https_open(req)
        pinned = ip

        class _Conn(http.client.HTTPSConnection):
            def connect(self):
                self.sock = _socket.create_connection(
                    (pinned, self.port or 443),
                    self.timeout,
                    self.source_address,
                )
                if self._tunnel_host:
                    self._tunnel()
                self.sock = self._context.wrap_socket(
                    self.sock, server_hostname=self._tunnel_host or self.host
                )

        try:
            return self.do_open(_Conn, req)
        except Exception:
            return super().https_open(req)


def build_github_opener() -> urllib.request.OpenerDirector:
    return urllib.request.build_opener(_PinnedHTTPSHandler())
