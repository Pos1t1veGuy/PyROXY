from typing import *
import os
import hashlib
import asyncio
import struct
import socket
import math
import ipaddress as ipa
from Cryptodome.Cipher import AES
from Cryptodome.Util import Counter
from Cryptodome.Util.Padding import pad, unpad

from ..base_cipher import IVCipher


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

        encrypted_header = self.encrypt(header)
        encrypted_methods = self.encrypt(methods_bytes)

        return self.iv + encrypted_header + encrypted_methods

    async def server_get_methods(self, socks_version: int, reader: asyncio.StreamReader) -> Dict[str, bool]:
        iv = await reader.readexactly(16)
        self._init_ciphers(iv)

        v, nm = await reader.readexactly(1), await reader.readexactly(1)
        version = self.decrypt(v)[0]
        nmethods = self.decrypt(nm)[0]

        if version != socks_version:
            raise ConnectionError(f"Unsupported SOCKS version: {version}")

        encrypted_methods = await reader.readexactly(nmethods)
        methods = self.decrypt(encrypted_methods)

        return {
            'supports_no_auth': 0x00 in methods,
            'supports_user_pass': 0x02 in methods
        }

    async def server_send_method_to_user(self, socks_version: int, method: int) -> bytes:
        return self.encrypt(struct.pack("!BB", socks_version, method))

    async def client_get_method(self, reader: asyncio.StreamReader) -> int:
        enc = await reader.readexactly(2)
        decrypted_response = self.decrypt(enc)
        version, method = struct.unpack("!BB", decrypted_response)

        if method == 0xFF:
            raise ConnectionError("No acceptable authentication methods.")

        return method

    async def server_auth_userpass(self, logins: Dict[str, str], reader: asyncio.StreamReader,
                                   writer: asyncio.StreamWriter) -> bool:
        encrypted_header = await reader.readexactly(2)
        version, ulen = struct.unpack("!BB", self.decrypt(encrypted_header))

        username = await reader.readexactly(ulen)
        username = (self.decrypt(username)).decode()

        plen_encrypted = await reader.readexactly(1)
        plen = (self.decrypt(plen_encrypted))[0]

        password = (await reader.readexactly(plen))
        password = (self.decrypt(password)).decode()

        if logins.get(username) == password:
            writer.write(self.encrypt(struct.pack("!BB", 1, 0)))
            await writer.drain()
            return username, password
        else:
            writer.write(self.encrypt(struct.pack("!BB", 1, 1)))
            await writer.drain()

    async def client_auth_userpass(self, username: str, password: str, reader: asyncio.StreamReader,
                                   writer: asyncio.StreamWriter) -> bool:
        username_bytes = username.encode()
        password_bytes = password.encode()

        writer.write(self.encrypt(struct.pack("!BB", 1, len(username_bytes))))
        writer.write(self.encrypt(username_bytes))
        writer.write(self.encrypt(bytes([len(password_bytes)])))
        writer.write(self.encrypt(password_bytes))
        await writer.drain()

        response = await reader.readexactly(2)
        version, status = struct.unpack("!BB", self.decrypt(response))

        if status != 0:
            raise ConnectionError("Authentication failed")

        return True

    async def client_command(self, socks_version: int, user_command: int, target_host: str, target_port: int) -> bytes:
        return self.encrypt(await super().client_command(socks_version, user_command, target_host, target_port))

    async def server_handle_command(self, socks_version: int, user_command_handlers: Dict[int, Callable],
                                    reader: asyncio.StreamReader) -> Tuple[str, int, Callable]:

        version, cmd, rsv, address_type = self.decrypt(await reader.readexactly(4))
        if version != socks_version:
            raise ConnectionError(f"Unsupported SOCKS version: {version}")

        if not cmd in user_command_handlers.keys():
            raise ConnectionError(f"Unsupported command: {cmd}, it must be one of {list(user_command_handlers.keys())}")
        cmd = user_command_handlers[cmd]

        match address_type:
            case 0x01:  # IPv4
                encrypted = await reader.readexactly(4 + 2)
                data = self.decrypt(encrypted)
                addr = '.'.join(map(str, data[:4]))
                port = int.from_bytes(data[4:], 'big')

            case 0x03:  # domain
                domain_len = (self.decrypt(await reader.readexactly(1)))[0]
                data = self.decrypt(await reader.readexactly(domain_len + 2))
                addr = data[:domain_len].decode()
                port = int.from_bytes(data[domain_len:], 'big')

            case 0x04:  # IPv6
                data = self.decrypt(await reader.readexactly(16 + 2))
                addr = socket.inet_ntop(socket.AF_INET6, data[:16])
                port = int.from_bytes(data[16:], 'big')

            case _:
                raise ConnectionError(f"Invalid address: {address_type}, it must be 0x01/0x03/0x04")

        return addr, port, cmd

    async def server_make_reply(self, socks_version: int, reply_code: int, address: str = '0', port: int = 0) -> bytes:
        return self.encrypt(
            await super().server_make_reply(socks_version, reply_code, address=address, port=port)
        )

    async def client_connect_confirm(self, reader: asyncio.StreamReader) -> Tuple[str, str]:
        hdr = self.decrypt(await reader.readexactly(4))
        ver, rep, rsv, atyp = hdr

        if ver != 0x05:
            raise ConnectionError(f"Invalid SOCKS version in reply: {ver}")
        if rep != 0x00:
            raise ConnectionError(f"SOCKS5 request failed, REP={rep}")

        match atyp:
            case 0x01:  # IPv4
                addr_port = self.decrypt(await reader.readexactly(4 + 2))
                addr_bytes, port_bytes = addr_port[:4], addr_port[4:]
                address = socket.inet_ntoa(addr_bytes)
            case 0x03:  # Domain
                len_byte = await reader.readexactly(1)
                domain_len = self.decrypt(len_byte)[0]
                addr_port = self.decrypt(await reader.readexactly(domain_len + 2))
                addr_bytes, port_bytes = addr_port[:domain_len], addr_port[domain_len:]
                address = addr_bytes.decode('idna')
            case 0x04:  # IPv6
                addr_port = self.decrypt(await reader.readexactly(16 + 2))
                addr_bytes, port_bytes = addr_port[:16], addr_port[16:]
                address = socket.inet_ntop(socket.AF_INET6, addr_bytes)
            case _:
                raise ConnectionError(f"Invalid ATYP in reply: {atyp}")

        return address, struct.unpack('!H', port_bytes)[0]


    def encrypt(self, data: bytes) -> bytes:
        if not self.encryptor is None:
            return self.encryptor.encrypt(data)
        else:
            raise OSError(f'{self.__class__.__name__} needs to specify IV (init vector) in constructor or handshake')

    def decrypt(self, data: bytes) -> bytes:
        if not self.encryptor is None:
            return self.decryptor.decrypt(data)
        else:
            raise OSError(f'{self.__class__.__name__} needs to specify IV (init vector) in constructor or handshake')


class AESCipherCBC(AESCipherCTR):
    def _init_ciphers(self, iv: bytes):
        self.encryptor = AES.new(self.key, AES.MODE_CBC, iv=iv)
        self.decryptor = AES.new(self.key, AES.MODE_CBC, iv=iv)
        self.iv = iv

    async def server_get_methods(self, socks_version: int, reader: asyncio.StreamReader) -> Dict[str, bool]:
        iv = await reader.readexactly(AES.block_size)
        self._init_ciphers(iv)

        encrypted_header = await reader.readexactly(AES.block_size)
        decrypted_header = self.decrypt(encrypted_header)
        version, nmethods = decrypted_header

        if version != socks_version:
            raise ConnectionError(f"Unsupported SOCKS version: {version}")

        padded_len = ((nmethods + AES.block_size - 1) // AES.block_size) * AES.block_size
        encrypted_methods = await reader.readexactly(padded_len)
        methods = self.decrypt(encrypted_methods)

        return {
            'supports_no_auth': 0x00 in methods,
            'supports_user_pass': 0x02 in methods
        }

    async def client_get_method(self, reader: asyncio.StreamReader) -> int:
        decrypted_response = self.decrypt(await reader.readexactly(AES.block_size))
        version, method = struct.unpack("!BB", decrypted_response[:2])

        if method == 0xFF:
            raise ConnectionError("No acceptable authentication methods.")

        return method

    async def server_auth_userpass(self, logins: Dict[str, str], reader: asyncio.StreamReader,
                                   writer: asyncio.StreamWriter) -> bool:
        header = self.decrypt(await reader.readexactly(AES.block_size))
        version, ulen = struct.unpack("!BB", header[:2])

        padded_ulen = ((ulen + AES.block_size - 1) // AES.block_size) * AES.block_size
        username = self.decrypt(await reader.readexactly(padded_ulen))
        username = username[:ulen].decode()

        plen = (self.decrypt(await reader.readexactly(AES.block_size)))[0]

        padded_plen = ((plen + AES.block_size - 1) // AES.block_size) * AES.block_size
        decrypted_password = self.decrypt(await reader.readexactly(padded_plen))
        password = decrypted_password[:plen].decode()

        if logins.get(username) == password:
            writer.write(self.encrypt(struct.pack("!BB", 1, 0)))
            await writer.drain()
            return username, password
        else:
            writer.write(self.encrypt(struct.pack("!BB", 1, 1)))
            await writer.drain()

    async def client_auth_userpass(self, username: str, password: str, reader: asyncio.StreamReader,
                                   writer: asyncio.StreamWriter) -> bool:
        username_bytes = username.encode()
        password_bytes = password.encode()

        writer.write(self.encrypt(struct.pack("!BB", 1, len(username_bytes))))
        writer.write(self.encrypt(username_bytes))
        writer.write(self.encrypt(bytes([len(password_bytes)])))
        writer.write(self.encrypt(password_bytes))
        await writer.drain()

        response = self.decrypt(await reader.readexactly(AES.block_size))
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

        first_block = self.encrypt(
            struct.pack("!BBBBB", socks_version, user_command, 0x00, atyp, length)
        )
        second_block = self.encrypt(addr_bytes + struct.pack("!H", target_port))
        return first_block + second_block

    async def server_handle_command(self, socks_version: int, user_command_handlers: Dict[int, Callable],
                                        reader: asyncio.StreamReader) -> Tuple[str, int, Callable]:

        header_raw = await reader.readexactly(16)
        header = self.decrypt(header_raw)
        version, cmd, rsv, address_type, length = struct.unpack("!BBBBB", header[:5])
        if version != socks_version:
            raise ConnectionError(f"Unsupported SOCKS version: {version}")

        if not cmd in user_command_handlers.keys():
            raise ConnectionError(f"Unsupported command: {cmd}, it must be one of {list(user_command_handlers.keys())}")
        cmd = user_command_handlers[cmd]

        match address_type:
            case 0x01:  # IPv4
                encrypted = await reader.readexactly(16)
                data = self.decrypt(encrypted)
                addr = '.'.join(map(str, data[:4]))
                port = int.from_bytes(data[4:], 'big')

            case 0x03:  # domain
                total_len = length + 2
                padded_len = ((total_len + 15) // 16) * 16
                data = self.decrypt(await reader.readexactly(padded_len))
                addr = data[:length].decode()
                port = int.from_bytes(data[length:], 'big')

            case 0x04:  # IPv6
                data = self.decrypt(await reader.readexactly(16 + 2))
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
            tail = f"{len(addr_data)}sH"

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
        return self.encrypt(first_header) + self.encrypt(second_header)

    async def client_connect_confirm(self, reader: asyncio.StreamReader) -> Tuple[str, str]:
        header_encrypted = await reader.readexactly(AES.block_size)
        header = self.decrypt(header_encrypted)

        try:
            ver, rep, _, atyp = header
            if ver != 0x05:
                raise ConnectionError(f"Invalid SOCKS version in reply: {ver}")
            if rep != 0x00:
                raise ConnectionError(f"SOCKS5 CONNECT failed with code {rep}")

        except Exception:
            raise ConnectionError(f"Invalid header received: {header}")

        match atyp:
            case 0x01:  # IPv4
                addr_port = self.decrypt(await reader.readexactly(AES.block_size))
                addr_bytes, port_bytes = addr_port[:4], addr_port[4:6]
                address = socket.inet_ntoa(addr_bytes)
            case 0x03:  # Domain
                domain_len = (self.decrypt(await reader.readexactly(AES.block_size)))[0]
                padded = ((total + AES.block_size - 1) // AES.block_size) * AES.block_size
                addr_port = self.decrypt(await reader.readexactly(padded))
                addr_bytes, port_bytes = addr_port[:domain_len], addr_port[domain_len:domain_len+2]
                address = addr_bytes.decode('idna')
            case 0x04:  # IPv6
                addr_port = self.decrypt(await reader.readexactly(math.ceil(32 / AES.block_size)))
                addr_bytes, port_bytes = addr_port[:16], addr_port[16:18]
                address = socket.inet_ntop(socket.AF_INET6, addr_bytes)
            case _:
                raise ConnectionError(f"Invalid ATYP in reply: {atyp}")

        return address, struct.unpack('!H', port_bytes)[0]


    def encrypt(self, data: bytes) -> bytes:
        if not self.encryptor is None:
            padded = pad(data, AES.block_size)
            res = self.encryptor.encrypt(padded)
            return res
        else:
            raise OSError(f'{self.__class__.__name__} needs to specify IV (init vector) in constructor or handshake')

    def decrypt(self, data: bytes) -> bytes:
        if not self.decryptor is None:
            decrypted = self.decryptor.decrypt(data)
            return unpad(decrypted, AES.block_size)
        else:
            raise OSError(f'{self.__class__.__name__} needs to specify IV (init vector) in constructor or handshake')