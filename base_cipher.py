from typing import *
import socket
import struct
import asyncio
import logging
import aiohttp
import json
import ipaddress as ipa
from functools import lru_cache

from .base_wrapper import Wrapper


'''
SOCKS5 HANDSHAKE STRUCTURE (client and server):

The ciphers encrypt the handshake using several methods and the main data stream.
To establish a SOCKS5 connection, both the client and server must follow a specific HANDSHAKE protocol,
which typically consists of 4–7 stages. This class defines symmetric methods for both parties.

▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬
[ CLIENT SIDE ]                         [ SERVER SIDE ]
▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬
0. client_start_handshake →              → server_start_handshake
   - *If you want it will custom start of your handshake. By default it is empty.
   
1. client_send_methods →              → server_get_methods
   - Client sends SOCKS version and list of supported auth methods.

2. client_get_method ←                ← server_send_method_to_user
   - Server selects an auth method and responds.

3. server_finish_handshake →             → client_finish_handshake
   - *Custom end of a handshake

4. client_auth_userpass →             → server_auth_userpass
   - If selected method is username/password (0x02), client authenticates.

5. client_command →                   → server_handle_command
   - Client requests to CONNECT, BIND or ASSOCIATE (usually 0x01 = TCP connect),
     and provides destination address and port.

6. client_connect_confirm ←           ← server_make_reply
   - Server replies with success or failure and bound address/port.

▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬

If the handshake is successful (reply code 0x00), the SOCKS tunnel is established.
All further traffic is sent over this tunnel.

After that:
- `encrypt(data)` and `decrypt(data)` are used to optionally obfuscate or secure traffic.
- These can be customized (e.g., with XOR, AES, session keys, etc.) to implement encryption
  or detection evasion mechanisms similar to obfs4 or ShadowSocks. Functions returns a package
  list.

Each `Cipher` subclass must implement or override:
- Handshake stages (client and/or server side)
- `encrypt(data: bytes) -> List[bytes]`
- `decrypt(data: bytes) -> List[bytes]`
'''


REPLYES = {
    0x00: "SUCCEEDED",
    0x01: "GENERAL_FAILURE",
    0x02: "CONNECTION_NOT_ALLOWED",
    0x03: "NETWORK_UNREACHABLE",
    0x04: "HOST_UNREACHABLE",
    0x05: "CONNECTION_REFUSED",
    0x06: "TTL_EXPIRED",
    0x07: "COMMAND_NOT_SUPPORTED",
    0x08: "ADDRESS_TYPE_NOT_SUPPORTED",
    0xFF: "CONNECTION_NOT_ALLOWED",
}
REPLYES_CODES = {
    "succeeded": 0x00,
    "failure": 0x01,
    "network_unreachable": 0x03,
    "host_unreachable": 0x04,
    "refused": 0x05,
    "ttl_expired": 0x06,
    "cmd_not_supported": 0x07,
    "atype_not_supported": 0x08,
    "not_allowed": 0xFF,
}


@lru_cache(maxsize=10000)
def fast_ipv4(data: bytes) -> str:
    return str(ipa.IPv4Address(data))

@lru_cache(maxsize=10000)
def fast_ipv6(data: bytes) -> str:
    return str(ipa.IPv6Address(data))

@lru_cache(maxsize=10000)
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

async def resolve_doh(domain: str, resolver_urls: Optional[list[str]] = None) -> list[str]:
    """
    Resolves a domain name using DNS over HTTPS (DoH).
    Returns a list of IPv4 addresses.
    """
    if not resolver_urls:
        resolver_urls = [
            "https://1.1.1.1/dns-query?name={domain}",
            "https://8.8.8.8/dns-query?name={domain}",
            "https://9.9.9.9/dns-query?name={domain}"
        ]

    headers = {"accept": "application/dns-json"}

    for url in resolver_urls:
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url.format(domain=f"{domain}&type=A"), headers=headers, timeout=3) as resp:
                    if resp.status != 200:
                        continue
                    text = await resp.text()
                    data = json.loads(text)
                    return [a["data"] for a in data.get("Answer", []) if a["type"] == 1]
        except:
            continue
    raise RuntimeError(f"Cannot resolve {domain} via DoH resolvers")


class Cipher:
    def __init__(self, *args, wrapper: Wrapper = Wrapper(), **kwargs):
        self.wrapper = wrapper
        self.client_hello = self.wrapper.client_hello
        self.server_hello = self.wrapper.server_hello
        self.handle_suspicious_client = self.wrapper.handle_suspicious_client
        self.is_client = False
        self.is_server = False
        self.is_handshaked = False
        self._init_args = args
        self._init_kwargs = {'wrapper': wrapper, **kwargs}

    def copy(self) -> 'Cipher':
        return self.__class__(*self._init_args, **self._init_kwargs)

    async def client_start_handshake(self, client: 'Socks5Client', cipher_index: int, proxying_mode: int,
                                 reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> bool:
        # [cipher index byte] + [proxying mode byte]
        writer.write(struct.pack("!BB", cipher_index, proxying_mode))
        await writer.drain()
        response = (await reader.readexactly(1))[0]
        return response == 0

    async def server_start_handshake(self, server: 'Socks5Server', ciphers: List['Cipher'], reader: asyncio.StreamReader,
                           writer: asyncio.StreamWriter) -> Tuple['Cipher', int]:
        # [cipher index byte] + [proxying mode byte]
        index, mode = struct.unpack("!BB", await reader.readexactly(2))
        try:
            cipher = ciphers[index]
        except IndexError:
            writer.write(b'\x01')
            await writer.drain()
            raise ConnectionError(f'Invalid cipher index received {index}')

        writer.write(b'\x00')
        await writer.drain()
        return cipher.copy(), mode

    async def client_send_methods(self, socks_version: int, methods: List[int]) -> List[bytes]:
        return [bytes([
            socks_version,
            len(methods),
            *methods,
        ])]

    async def server_get_methods(self, socks_version: int, reader: asyncio.StreamReader) -> Dict[str, bool]:
        version, nmethods = await reader.readexactly(2)
        if version != socks_version:
            raise ConnectionError(f"Unsupported SOCKS version: {version}")

        methods = await reader.readexactly(nmethods)

        return {
            'supports_no_auth': 0x00 in methods,
            'supports_gss_api': 0x01 in methods,
            'supports_user_pass': 0x02 in methods,
        }

    async def server_send_method_to_user(self, socks_version: int, method: int) -> List[bytes]:
        return [bytes([socks_version, method])]

    async def client_get_method(self, socks_version: int, reader: asyncio.StreamReader) -> int:
        response = await reader.readexactly(2)

        if response[0] != socks_version:
            raise ConnectionError(f"Unsupported SOCKS version: {version}")
        if response[1] == 0xFF:
            raise ConnectionError("No acceptable authentication methods.")

        return response[1]

    async def server_auth_userpass(self, db_handler: 'Handler', reader: asyncio.StreamReader,
                            writer: asyncio.StreamWriter) -> Optional[Tuple[str, str, str]]:
        auth_version = (await reader.readexactly(1))[0]

        if auth_version == 1:
            username_length = (await reader.readexactly(1))[0]
            username = (await reader.readexactly(username_length)).decode()

            pw_length = (await reader.readexactly(1))[0]
            pw = (await reader.readexactly(pw_length)).decode()
            db_pw, db_key = db_handler.get_user(username)

            if db_pw == pw:
                writer.write(bytes([1, 0]))
                await writer.drain()
                return username, pw, db_key
            else:
                writer.write(bytes([1, 1]))
                await writer.drain()
                raise ConnectionError(f"Wrong authentication data: uname={username}, pw={pw}")

    async def client_auth_userpass(self, username: str, password: str, reader: asyncio.StreamReader,
                                   writer: asyncio.StreamWriter) -> bool:
        username_bytes = username.encode()
        password_bytes = password.encode()

        data = bytes([0x01, len(username_bytes)]) + username_bytes + bytes([len(password_bytes)]) + password_bytes
        writer.write(data)
        await writer.drain()

        resp = await reader.readexactly(2)
        try:
            return resp[1] == REPLYES_CODES['succeeded']
        except IndexError:
            raise ConnectionError(f'Invalid answer received {resp}')

    async def server_finish_handshake(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> bool:
        return True

    async def client_finish_handshake(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> bool:
        return True

    async def client_command(self, socks_version: int, user_command: int, target_host: str, target_port: int) -> bytes:
        addr_bytes = b''
        atyp = 0x01
        length = 4
        try:
            ip = ipa.ip_address(target_host)
            addr_bytes = ip.packed
            if ip.version == 6:  # IPv6
                atyp = 0x04
                length = 16
        except ValueError: # domain
            atyp = 0x03
            addr_bytes = target_host.encode("idna")
            length = len(addr_bytes)
            if length > 255:
                raise ValueError("Domain name too long for SOCKS5")

        return struct.pack("!BBBB", socks_version, user_command, 0x00, atyp) + addr_bytes + struct.pack("!H", target_port)

    async def server_handle_command(self, socks_version: int, user_command_handlers: Dict[int, Callable],
                                    reader: asyncio.StreamReader,
                                    address_resolver: Callable[[bytes, int], Tuple[str, int]] = get_address
                                    ) -> Tuple[str, int, Callable]:

        version, cmd, rsv, address_type = await reader.readexactly(4)
        if version != socks_version:
            raise ConnectionError(f"Unsupported SOCKS version: {version}")

        if not cmd in user_command_handlers.keys():
            raise ConnectionError(f"Unsupported command: {cmd}, it must be one of {list(user_command_handlers.keys())}")
        cmd = user_command_handlers[cmd]

        match address_type:
            case 0x01: # IPv4
                addr_bytes = await reader.readexactly(4 + 2)
            case 0x03: # domain
                domain_length = (await reader.readexactly(1))[0]
                addr_bytes = await reader.readexactly(domain_length + 2)
            case 0x04: # IPv6
                addr_bytes = await reader.readexactly(16 + 2)
            case _:
                raise ConnectionError(f"Invalid address: {address_type}, it must be 0x01/0x03/0x04")

        return *address_resolver(addr_bytes, address_type), cmd

    async def server_make_reply(self, socks_version: int, reply_code: int, address: str = '0', port: int = 0) -> List[bytes]:
        address_type = 0x01
        length = 4
        addr_data = socket.inet_aton("0.0.0.0")

        try:
            ip = ipa.ip_address(address)
            addr_data = ip.packed
            if ip.version == 6:
                address_type = 0x04
                addr_data = ip.packed
                length = 16

        except ValueError:
            address_type = 0x03
            addr_bytes = address.encode('idna')
            length = len(addr_bytes)
            if length > 255:
                raise ValueError("Domain name too long for SOCKS5 protocol")

            addr_data = bytes([length]) + addr_bytes
            length += 1

        except:
            address_type = 0x01
            port = 0

        return [struct.pack(
            f"!BBBB{length}sH",
            socks_version,
            reply_code,
            0x00,  # RSV
            address_type,
            addr_data,
            port
        )]

    async def client_connect_confirm(self, reader: asyncio.StreamReader) -> Tuple[str, str]:
        hdr = await reader.readexactly(4)
        ver, rep, rsv, atyp = hdr

        if ver != 0x05:
            raise ConnectionError(f"Invalid SOCKS version in reply: {ver}")
        if rep != 0x00:
            raise ConnectionError(f"SOCKS5 request failed {REPLYES[rep]}")

        if atyp == 0x01:  # IPv4
            addr_bytes = await reader.readexactly(4)
            port_bytes = await reader.readexactly(2)
            address = socket.inet_ntoa(addr_bytes)

        elif atyp == 0x03:  # Domain
            domain_len = await reader.readexactly(1)[0]
            addr_bytes = await reader.readexactly(domain_len)
            port_bytes = await reader.readexactly(2)
            address = addr_bytes.decode('idna')

        elif atyp == 0x04:  # IPv6
            addr_bytes = await reader.readexactly(16)
            port_bytes = await reader.readexactly(2)
            address = socket.inet_ntop(socket.AF_INET6, addr_bytes)

        else:
            raise ConnectionError(f"Invalid ATYP in reply: {atyp}")

        return address, struct.unpack('!H', port_bytes)[0]


    def encrypt(self, data: bytes) -> List[bytes]:
        return [self.wrapper.wrap(data)]

    def decrypt(self, data: bytes) -> List[bytes]:
        return [self.wrapper.unwrap(data)]