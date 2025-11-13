from typing import *
import aiohttp
import json
import requests
import certifi
import ipaddress as ipa
from functools import lru_cache


@lru_cache(maxsize=10000)
def fast_ipv4(data: bytes) -> str:
    return str(ipa.IPv4Address(data))

@lru_cache(maxsize=10000)
def fast_ipv6(data: bytes) -> str:
    return str(ipa.IPv6Address(data))

def resolve_domain(domain: str, port: int) -> tuple[str, int]:
    infos = socket.getaddrinfo(domain, port, type=socket.SOCK_DGRAM)
    for fam, *_rest, sockaddr in infos:
        if fam in (socket.AF_INET, socket.AF_INET6):
            return sockaddr[0], sockaddr[1]
    raise ConnectionError(f"Cannot resolve {domain}")

@lru_cache(maxsize=10000)
def encode_ip(remote_ip: str) -> tuple[int, bytes]:
    if '.' in remote_ip:
        try:
            return 0x01, socket.inet_pton(socket.AF_INET, remote_ip)
        except OSError:
            pass
    if ':' in remote_ip:
        try:
            return 0x04, socket.inet_pton(socket.AF_INET6, remote_ip)
        except OSError:
            pass

    dom = remote_ip.encode("idna")[:255]
    return 0x03, bytes([len(dom)]) + dom

@lru_cache(maxsize=10000)
def get_address(data: bytes, address_type: int) -> Tuple[str, int]:
    match address_type:
        case 0x01:  # IPv4
            addr = fast_ipv4(data[:4])
            port = int.from_bytes(data[4:6], 'big')
        case 0x03:  # domain
            addr = data[:-2].decode()
            port = int.from_bytes(data[-2:], 'big')
        case 0x04:  # IPv6
            addr = fast_ipv6(data[:16])
            port = int.from_bytes(data[16:18], 'big')
        case _:
            raise ConnectionError(f"Invalid address: {address_type}, it must be 0x01/0x03/0x04")
    return addr, port


def resolve_domain_doh(domain: str, retry: int = 5, return_ttl: bool = False) -> str | Tuple[str, int]:
    try:
        headers = {"accept": "application/dns-json"}
        params = {"name": domain, "type": "A"}
        r = requests.get("https://cloudflare-dns.com/dns-query", headers=headers, params=params, timeout=5,
                         verify=certifi.where())
        data = json.loads(r.text)

        for ans in data.get("Answer", []):
            if ans.get("type") == 1:  # A record
                if return_ttl:
                    return ans["data"], ans.get("TTL", 300)
                return ans["data"]

        for ans in reversed(data.get("Answer", [])):
            if ans.get("type") == 5:  # CNAME
                cname = ans["data"].rstrip(".")
                return resolve_domain_doh(cname, retry=5, return_ttl=return_ttl)

        if data.get("Answer"):
            ans = data["Answer"][0]
            if return_ttl:
                return ans["data"], ans.get("TTL", 300)
            return ans["data"]

        raise ConnectionError(f'No valid DNS answer for {domain}')
    except:
        if retry > 0:
            return resolve_domain_doh(domain, retry=retry-1, return_ttl=return_ttl)
        else:
            raise ConnectionError(f'Can not resolve domain {domain}')