import traceback
from typing import *
import asyncio
import socket
import struct

from .wrappers import HTTP_WS_Wrapper
from .ciphers import AESCipherCTR
from ..base_cipher import Cipher


class AESCipherCTR_HTTPWS(AESCipherCTR):
    def __init__(self, *args, http_path: str = "/", ws_path: str = "/ws/", host: str = "example.com",  **kwargs):
        self.wrapper = HTTP_WS_Wrapper(host=host, http_path=http_path, ws_path=ws_path)
        self.server_hello = self.wrapper.server_hello
        self.client_hello = self.wrapper.client_hello
        super().__init__(*args, **kwargs)

    async def client_send_methods(self, socks_version: int, methods: List[int]) -> bytes:
        if self.iv is None:
            raise ValueError("IV must be initialized before sending methods")

        header = struct.pack("!BB", socks_version, len(methods))

        methods_bytes = struct.pack(f"!{len(methods)}B", *methods)
        return self.wrapper.wrap(self.iv + self.encrypt(header + methods_bytes, wrap=False))

    async def server_get_methods(self, socks_version: int, reader: asyncio.StreamReader) -> Dict[str, bool]:
        header, length, mask = await self.wrapper.cut_ws_header(reader)
        iv = await reader.readexactly(16)
        self._init_ciphers(iv)

        version, nmethods = struct.unpack("!BB", self.decrypt(await reader.readexactly(2), mask=mask, wrap=False))

        if version != socks_version:
            raise ConnectionError(f"Unsupported SOCKS version: {version}")

        encrypted_methods = await reader.readexactly(nmethods)
        methods = self.decrypt(encrypted_methods, mask=mask, wrap=False)

        return {
            'supports_no_auth': 0x00 in methods,
            'supports_user_pass': 0x02 in methods
        }

    async def server_send_method_to_user(self, socks_version: int, method: int) -> bytes:
        return self.encrypt(struct.pack("!BB", socks_version, method), wrap=True)

    async def client_get_method(self, socks_version: int, reader: asyncio.StreamReader) -> int:
        header, length, mask = await self.wrapper.cut_ws_header(reader)
        enc = await reader.readexactly(2)
        version, method = struct.unpack("!BB", self.decrypt(enc, mask=mask, wrap=False))

        if version != socks_version:
            raise ConnectionError(f"Unsupported SOCKS version: {version}")
        if method == 0xFF:
            raise ConnectionError("No acceptable authentication methods.")

        return method

    async def server_auth_userpass(self, logins: Dict[str, str], reader: asyncio.StreamReader,
                                   writer: asyncio.StreamWriter) -> Optional[Tuple[str, str]]:
        header, length, mask = await self.wrapper.cut_ws_header(reader)
        encrypted_header = await reader.readexactly(2)
        auth_version, ulen = struct.unpack("!BB", self.decrypt(encrypted_header, mask=mask, wrap=False))

        username = await reader.readexactly(ulen)
        username = self.decrypt(username, mask=mask, wrap=False).decode()

        plen_encrypted = await reader.readexactly(1)
        plen = self.decrypt(plen_encrypted, mask=mask, wrap=False)[0]

        password = await reader.readexactly(plen)
        password = self.decrypt(password, mask=mask, wrap=False).decode()

        if logins.get(username) == password:
            writer.write(self.encrypt(struct.pack("!BB", 1, 0), wrap=True))
            await writer.drain()
            return username, password
        else:
            writer.write(self.encrypt(struct.pack("!BB", 1, 1), wrap=True))
            await writer.drain()

    async def client_auth_userpass(self, username: str, password: str, reader: asyncio.StreamReader,
                                   writer: asyncio.StreamWriter) -> bool:
        username_bytes = username.encode()
        password_bytes = password.encode()

        writer.write(self.encrypt(struct.pack("!BB", 1, len(username_bytes)), wrap=True))
        writer.write(self.encrypt(username_bytes, wrap=False))
        writer.write(self.encrypt(bytes([len(password_bytes)]), wrap=False))
        writer.write(self.encrypt(password_bytes, wrap=False))
        await writer.drain()

        header, length, mask = await self.wrapper.cut_ws_header(reader)
        response = await reader.readexactly(2)
        version, status = struct.unpack("!BB", self.decrypt(response, mask=mask, wrap=False))

        if status != 0:
            raise ConnectionError("Authentication failed")

        return True

    async def client_command(self, socks_version: int, user_command: int, target_host: str, target_port: int) -> bytes:
        return self.encrypt(
            await Cipher.client_command(socks_version, user_command, target_host, target_port), wrap=True
        )

    async def server_handle_command(self, socks_version: int, user_command_handlers: Dict[int, Callable],
                                    reader: asyncio.StreamReader) -> Tuple[str, int, Callable]:
        header, length, mask = await self.wrapper.cut_ws_header(reader)
        raw = await reader.readexactly(4)
        version, cmd, rsv, address_type = self.decrypt(raw, mask=mask, wrap=False)
        if version != socks_version:
            raise ConnectionError(f"Unsupported SOCKS version: {version}")

        if not cmd in user_command_handlers.keys():
            raise ConnectionError(f"Unsupported command: {cmd}, it must be one of {list(user_command_handlers.keys())}")
        cmd = user_command_handlers[cmd]

        match address_type:
            case 0x01:  # IPv4
                encrypted = await reader.readexactly(4 + 2)
                data = self.decrypt(encrypted, mask=mask, wrap=False)
                addr = '.'.join(map(str, data[:4]))
                port = int.from_bytes(data[4:], 'big')

            case 0x03:  # domain
                domain_len = self.decrypt(await reader.readexactly(1), wrap=False)[0]
                data = self.decrypt(await reader.readexactly(domain_len + 2), mask=mask, wrap=False)
                addr = data[:domain_len].decode()
                port = int.from_bytes(data[domain_len:], 'big')

            case 0x04:  # IPv6
                data = self.decrypt(await reader.readexactly(16 + 2), mask=mask, wrap=False)
                addr = socket.inet_ntop(socket.AF_INET6, data[:16])
                port = int.from_bytes(data[16:], 'big')

            case _:
                raise ConnectionError(f"Invalid address: {address_type}, it must be 0x01/0x03/0x04")

        return addr, port, cmd

    async def server_make_reply(self, socks_version: int, reply_code: int, address: str = '0', port: int = 0) -> bytes:
        return self.encrypt(
            await Cipher.server_make_reply(socks_version, reply_code, address=address, port=port), wrap=True
        )

    async def client_connect_confirm(self, reader: asyncio.StreamReader) -> Tuple[str, str]:
        header, length, mask = await self.wrapper.cut_ws_header(reader)
        hdr = self.decrypt(await reader.readexactly(4), mask=mask, wrap=False)
        ver, rep, rsv, atyp = hdr

        if ver != 0x05:
            raise ConnectionError(f"Invalid SOCKS version in reply: {ver}")
        if rep != 0x00:
            raise ConnectionError(f"SOCKS5 request failed, REP={rep}")

        match atyp:
            case 0x01:  # IPv4
                addr_port = self.decrypt(await reader.readexactly(4 + 2), mask=mask, wrap=False)
                addr_bytes, port_bytes = addr_port[:4], addr_port[4:]
                address = socket.inet_ntoa(addr_bytes)
            case 0x03:  # Domain
                len_byte = await reader.readexactly(1)
                domain_len = self.decrypt(len_byte, mask=mask, wrap=False)[0]
                addr_port = self.decrypt(await reader.readexactly(domain_len + 2), mask=mask, wrap=False)
                addr_bytes, port_bytes = addr_port[:domain_len], addr_port[domain_len:]
                address = addr_bytes.decode('idna')
            case 0x04:  # IPv6
                addr_port = self.decrypt(await reader.readexactly(16 + 2), mask=mask, wrap=False)
                addr_bytes, port_bytes = addr_port[:16], addr_port[16:]
                address = socket.inet_ntop(socket.AF_INET6, addr_bytes)
            case _:
                raise ConnectionError(f"Invalid ATYP in reply: {atyp}")

        return address, struct.unpack('!H', port_bytes)[0]


    def encrypt(self, data: bytes, wrap: bool = False, mask: bool = False, wrap1: bool = False) -> bytes:
        data = super().encrypt(data)

        if wrap:
            return self.wrapper.wrap(data, mask=self.is_client and mask)
        elif mask:
            return self.wrapper.mask(data, self.wrapper.rmask)
        else:
            return data

    def decrypt(self, data: bytes, wrap: bool = False, mask: bytes = b'') -> bytes:
        if wrap:
            data = self.wrapper.unwrap(data)
        elif mask != b'':
            data = self.wrapper.mask(data, mask)
        return super().decrypt(data)