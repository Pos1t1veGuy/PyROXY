from typing import *
import os
import hashlib
import asyncio
import struct
from Cryptodome.Cipher import AES
from Cryptodome.Util import Counter

from ..base_cipher import Cipher


class AESCipher(Cipher):
    def __init__(self, key: bytes, iv: Optional[bytes] = None):
        super().__init__()
        assert len(key) in (16, 24, 32), "AES key must be 128, 192, or 256 bits"
        self.key = key
        self.iv = iv
        self.encryptor = None
        self.decryptor = None

        if iv is not None:
            self._init_ciphers(iv)

    def _init_ciphers(self, iv: bytes):
        ctr_enc = Counter.new(128, initial_value=int.from_bytes(iv, byteorder='big'))
        ctr_dec = Counter.new(128, initial_value=int.from_bytes(iv, byteorder='big'))

        self.encryptor = AES.new(self.key, AES.MODE_CTR, counter=ctr_enc)
        self.decryptor = AES.new(self.key, AES.MODE_CTR, counter=ctr_dec)
        self.iv = iv

    async def client_send_methods(self, socks_version: int, methods: List[int]) -> bytes:
        if self.iv is None:
            raise ValueError("IV must be initialized before sending methods")

        header = struct.pack("!BB", socks_version, len(methods))

        methods_bytes = struct.pack(f"!{len(methods)}B", *methods)

        encrypted_header = await self.encrypt(header)
        encrypted_methods = await self.encrypt(methods_bytes)

        return self.iv + encrypted_header + encrypted_methods

    async def server_get_methods(self, socks_version: int, reader: asyncio.StreamReader) -> Dict[str, bool]:
        iv = await reader.readexactly(16)
        self._init_ciphers(iv)

        encrypted_header = await reader.readexactly(2)
        decrypted_header = await self.decrypt(encrypted_header)
        version, nmethods = decrypted_header

        if version != socks_version:
            raise ConnectionError(f"Unsupported SOCKS version: {version}")

        encrypted_methods = await reader.readexactly(nmethods)
        methods = await self.decrypt(encrypted_methods)

        return {
            'supports_no_auth': 0x00 in methods,
            'supports_user_pass': 0x02 in methods
        }

    async def server_send_method_to_user(self, socks_version: int, method: int) -> bytes:
        return await self.encrypt(struct.pack("!BB", socks_version, method))

    async def client_get_method(self, reader: asyncio.StreamReader) -> int:
        decrypted_response = await self.decrypt(await reader.readexactly(2))
        version, method = struct.unpack("!BB", decrypted_response)

        if method == 0xFF:
            raise ConnectionError("No acceptable authentication methods.")

        return method

    async def server_auth_userpass(self, logins: Dict[str, str], reader: asyncio.StreamReader,
                                   writer: asyncio.StreamWriter) -> bool:
        encrypted_header = await reader.readexactly(2)
        version, ulen = struct.unpack("!BB", await self.decrypt(encrypted_header))

        username = (await reader.readexactly(ulen))
        username = await self.decrypt(username).decode()

        plen_encrypted = await reader.readexactly(1)
        plen = await self.decrypt(plen_encrypted)[0]

        password = (await reader.readexactly(plen))
        password = await self.decrypt(password).decode()

        if logins.get(username) == password:
            writer.write(await self.encrypt(struct.pack("!BB", 1, 0)))
            await writer.drain()
            return True
        else:
            writer.write(await self.encrypt(struct.pack("!BB", 1, 1)))
            await writer.drain()
            return False

    async def client_auth_userpass(self, username: str, password: str, reader: asyncio.StreamReader,
                                   writer: asyncio.StreamWriter) -> bool:
        username_bytes = username.encode()
        password_bytes = password.encode()

        writer.write(await self.encrypt(struct.pack("!BB", 1, len(username_bytes))))
        writer.write(await self.encrypt(username_bytes))
        writer.write(await self.encrypt(bytes([len(password_bytes)])))
        writer.write(await self.encrypt(password_bytes))
        await writer.drain()

        response = await reader.readexactly(2)
        version, status = struct.unpack("!BB", await self.decrypt(response))

        if status != 0:
            raise ConnectionError("Authentication failed")

        return True

    async def client_command(self, socks_version: int, user_command: int, target_host: str, target_port: int) -> bytes:
        return await self.encrypt(await super().client_command(socks_version, user_command, target_host, target_port))

    async def server_handle_command(self, socks_version: int, user_command_handlers: Dict[int, Callable],
                                    reader: asyncio.StreamReader) -> Tuple[str, int, Callable]:

        version, cmd, rsv, address_type = await self.decrypt(await reader.readexactly(4))
        if version != socks_version:
            raise ConnectionError(f"Unsupported SOCKS version: {version}")

        if not cmd in user_command_handlers.keys():
            raise ConnectionError(f"Unsupported command: {cmd}, it must be one of {list(user_command_handlers.keys())}")
        cmd = user_command_handlers[cmd]

        match address_type:
            case 0x01:  # IPv4
                encrypted = await reader.readexactly(4 + 2)
                data = await self.decrypt(encrypted)
                addr = '.'.join(map(str, data[:4]))
                port = int.from_bytes(data[4:], 'big')

            case 0x03:  # domain
                domain_len = (await self.decrypt(await reader.readexactly(1)))[0]
                data = await self.decrypt(await reader.readexactly(domain_len + 2))
                addr = data[:domain_len].decode()
                port = int.from_bytes(data[domain_len:], 'big')

            case 0x04:  # IPv6
                data = await self.decrypt(await reader.readexactly(16 + 2))
                addr = socket.inet_ntop(socket.AF_INET6, data[:16])
                port = int.from_bytes(data[16:], 'big')

            case _:
                raise ConnectionError(f"Invalid address: {address_type}, it must be 0x01/0x03/0x04")

        return addr, port, cmd

    async def server_make_reply(self, socks_version: int, reply_code: int, address: str = '0', port: int = 0) -> bytes:
        return await self.encrypt(
            await super().server_make_reply(socks_version, reply_code, address=address, port=port)
        )

    async def client_connect_confirm(self, reader: asyncio.StreamReader) -> bool:
        header_encrypted = await reader.readexactly(4)
        header = await self.decrypt(header_encrypted)

        try:
            ver, rep, _, atyp = header
            if rep != 0x00:
                raise ConnectionError(f"SOCKS5 CONNECT failed with code {rep:02x}")
        except Exception:
            raise ConnectionError(f"Invalid header received: {header}")

        match atyp:
            case 0x01:  # IPv4
                encrypted = await reader.readexactly(4 + 2)
                _ = await self.decrypt(encrypted)
            case 0x03:  # Domain
                len_byte = await reader.readexactly(1)
                domain_len = await self.decrypt(len_byte)[0]
                encrypted = await reader.readexactly(domain_len + 2)
                _ = await self.decrypt(encrypted)
            case 0x04:  # IPv6
                encrypted = await reader.readexactly(16 + 2)
                _ = await self.decrypt(encrypted)
            case _:
                raise ConnectionError(f"Invalid address type: {atyp}")

        return True


    async def encrypt(self, data: bytes) -> bytes:
        return self.encryptor.encrypt(data)

    async def decrypt(self, data: bytes) -> bytes:
        return self.decryptor.decrypt(data)