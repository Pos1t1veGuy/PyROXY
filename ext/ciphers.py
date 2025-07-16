from typing import *
import os
import hashlib
import asyncio
import struct
import socket
import ipaddress as ipa
from Cryptodome.Cipher import AES
from Cryptodome.Util import Counter
from Cryptodome.Util.Padding import pad, unpad

from ..base_cipher import Cipher, IVCipher


class AESCipherCTR(IVCipher):
    def __init__(self, key: bytes, iv: Optional[bytes] = None):
        assert len(key) in (16, 24, 32), "AES key must be 128, 192, or 256 bits"
        super().__init__(key, iv=iv)

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

        username = await reader.readexactly(ulen)
        username = (await self.decrypt(username)).decode()

        plen_encrypted = await reader.readexactly(1)
        plen = (await self.decrypt(plen_encrypted))[0]

        password = (await reader.readexactly(plen))
        password = (await self.decrypt(password)).decode()

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


class AESCipherCBC(AESCipherCTR):
    def __init__(self, key: bytes, iv: Optional[bytes] = None):
        assert len(key) in (16, 24, 32), "AES key must be 128, 192, or 256 bits"
        super().__init__(key, iv=iv)
        self.bytes_block = 16

    def _init_ciphers(self, iv: bytes):
        self.encryptor = AES.new(self.key, AES.MODE_CBC, iv=iv)
        self.decryptor = AES.new(self.key, AES.MODE_CBC, iv=iv)
        self.iv = iv

    async def server_get_methods(self, socks_version: int, reader: asyncio.StreamReader) -> Dict[str, bool]:
        iv = await reader.readexactly(AES.block_size)
        self._init_ciphers(iv)

        encrypted_header = await reader.readexactly(AES.block_size)
        decrypted_header = await self.decrypt(encrypted_header)
        version, nmethods = decrypted_header

        if version != socks_version:
            raise ConnectionError(f"Unsupported SOCKS version: {version}")

        padded_len = ((nmethods + AES.block_size - 1) // AES.block_size) * AES.block_size
        encrypted_methods = await reader.readexactly(padded_len)
        methods = await self.decrypt(encrypted_methods)

        return {
            'supports_no_auth': 0x00 in methods,
            'supports_user_pass': 0x02 in methods
        }

    async def client_get_method(self, reader: asyncio.StreamReader) -> int:
        decrypted_response = await self.decrypt(await reader.readexactly(AES.block_size))
        version, method = struct.unpack("!BB", decrypted_response[:2])

        if method == 0xFF:
            raise ConnectionError("No acceptable authentication methods.")

        return method

    async def server_auth_userpass(self, logins: Dict[str, str], reader: asyncio.StreamReader,
                                   writer: asyncio.StreamWriter) -> bool:
        header = await self.decrypt(await reader.readexactly(AES.block_size))
        version, ulen = struct.unpack("!BB", header[:2])

        padded_ulen = ((ulen + AES.block_size - 1) // AES.block_size) * AES.block_size
        username = await self.decrypt(await reader.readexactly(padded_ulen))
        username = username[:ulen].decode()

        plen = (await self.decrypt(await reader.readexactly(AES.block_size)))[0]

        padded_plen = ((plen + AES.block_size - 1) // AES.block_size) * AES.block_size
        decrypted_password = await self.decrypt(await reader.readexactly(padded_plen))
        password = decrypted_password[:plen].decode()

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

        response = await self.decrypt(await reader.readexactly(AES.block_size))
        version, status = struct.unpack("!BB", response)

        if status != 0:
            raise ConnectionError("Authentication failed")

        return True

    async def client_command(self, socks_version: int, user_command: int, target_host: str, target_port: int) -> bytes:
        addr_bytes = b''
        length = 4
        try:
            ip = ipa.ip_address(target_host)
            if ip.version == 4:  # IPv4
                atyp = 0x01
                addr_part = ip.packed
            else:  # IPv6
                atyp = 0x04
                addr_part = ip.packed
                length = 16
        except ValueError:  # domain
            atyp = 0x03
            addr_bytes = target_host.encode("idna")
            if len(addr_bytes) > 255:
                raise ValueError("Domain name too long for SOCKS5")
            length = len(addr_bytes)

        first_block = await self.encrypt(
            struct.pack("!BBBBB", socks_version, user_command, 0x00, atyp, length)
        )
        second_block = await self.encrypt(addr_bytes + struct.pack("!H", target_port))
        return first_block + second_block

    async def server_handle_command(self, socks_version: int, user_command_handlers: Dict[int, Callable],
                                        reader: asyncio.StreamReader) -> Tuple[str, int, Callable]:

        header_raw = await reader.readexactly(16)
        header = self.decryptor.decrypt(header_raw) ####
        version, cmd, rsv, address_type, length = struct.unpack("!BBBBB", header[:5])
        if version != socks_version:
            raise ConnectionError(f"Unsupported SOCKS version: {version}")

        if not cmd in user_command_handlers.keys():
            raise ConnectionError(f"Unsupported command: {cmd}, it must be one of {list(user_command_handlers.keys())}")
        cmd = user_command_handlers[cmd]

        match address_type:
            case 0x01:  # IPv4
                encrypted = await reader.readexactly(16)
                data = await self.decrypt(encrypted)
                addr = '.'.join(map(str, data[:4]))
                port = int.from_bytes(data[4:], 'big')

            case 0x03:  # domain
                total_len = length + 2
                padded_len = ((total_len + 15) // 16) * 16
                data = await self.decrypt(await reader.readexactly(padded_len))
                addr = data[:length].decode()
                port = int.from_bytes(data[length:], 'big')

            case 0x04:  # IPv6
                data = await self.decrypt(await reader.readexactly(16 + 2))
                addr = socket.inet_ntop(socket.AF_INET6, data[:16])
                port = int.from_bytes(data[16:], 'big')

            case _:
                raise ConnectionError(f"Invalid address: {address_type}, it must be 0x01/0x03/0x04")

        return addr, port, cmd

    async def server_make_reply(self, socks_version: int, reply_code: int, address: str = '0', port: int = 0) -> bytes:
        address_type = 0x01
        head = "!BBBB"  # до address_type
        addr_data = socket.inet_aton("0.0.0.0")
        tail = "4sH"  # addr_data + port

        try:
            ip = ipa.ip_address(address)

            if ip.version == 4:
                addr_data = ip.packed

            elif ip.version == 6:
                address_type = 0x04
                addr_data = ip.packed
                tail = "16sH"

        except ValueError:
            addr_bytes = address.encode('idna')
            if len(addr_bytes) > 255:
                raise ValueError("Domain name too long for SOCKS5 protocol")

            address_type = 0x03
            addr_data = bytes([len(addr_bytes)]) + addr_bytes
            tail = f"{len(addr_data)}sH"  # длина addr_data + порт

        except:
            address_type = 0x01
            port = 0

        first_header = struct.pack(
            head,
            socks_version,
            reply_code,
            0x00,  # RSV
            address_type
        )
        second_header = struct.pack(
            tail,
            addr_data,
            port
        )
        return await self.encrypt(first_header) + await self.encrypt(second_header)

    async def client_connect_confirm(self, reader: asyncio.StreamReader) -> bool:
        header_encrypted = await reader.readexactly(AES.block_size)
        header = await self.decrypt(header_encrypted)

        try:
            ver, rep, _, atyp = header
            if rep != 0x00:
                raise ConnectionError(f"SOCKS5 CONNECT failed with code {rep:02x}")
        except Exception:
            raise ConnectionError(f"Invalid header received: {header}")

        match atyp:
            case 0x01:  # IPv4
                encrypted = await reader.readexactly(AES.block_size)
                _ = await self.decrypt(encrypted)
            case 0x03:  # Domain
                len_block = await reader.readexactly(AES.block_size)
                domain_len = (await self.decrypt(len_block))[0]
                padded = ((total + AES.block_size - 1) // AES.block_size) * AES.block_size
                encrypted = await reader.readexactly(padded)
                _ = await self.decrypt(encrypted)
            case 0x04:  # IPv6
                encrypted = await reader.readexactly(32)
                _ = await self.decrypt(encrypted)
            case _:
                raise ConnectionError(f"Invalid address type: {atyp}")

        return True


    async def encrypt(self, data: bytes) -> bytes:
        # print(1, len(data))
        padded = pad(data, AES.block_size)
        # print(2, len(padded))
        res = self.encryptor.encrypt(padded)
        # print(3,len(res), res)
        return res

    async def decrypt(self, data: bytes, padded: bool = True) -> bytes:
        # print(3, len(data))
        decrypted = self.decryptor.decrypt(data)
        # print(4, len(decrypted))
        return unpad(decrypted, AES.block_size) if padded else decrypted