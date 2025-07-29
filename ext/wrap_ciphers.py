from typing import *
import asyncio
import socket
import struct

from .wrappers import HTTP_WS_Wrapper
from .ciphers import AES_CTR, ChaCha20_Poly1305
from ..base_cipher import Cipher, REPLYES


class AES_CTR_HTTPWS(AES_CTR):
    def __init__(self, *args, http_path: str = "/", ws_path: str = "/ws/", host: str = "example.com",  **kwargs):
        self.wrapper = HTTP_WS_Wrapper(host=host, http_path=http_path, ws_path=ws_path)
        self.server_hello = self.wrapper.server_hello
        self.client_hello = self.wrapper.client_hello
        super().__init__(*args, **kwargs)

    async def client_send_methods(self, socks_version: int, methods: List[int]) -> List[bytes]:
        if self.iv is None:
            raise ValueError("IV must be initialized before sending methods")

        header = struct.pack("!BB", socks_version, len(methods))

        methods_bytes = struct.pack(f"!{len(methods)}B", *methods)
        return [self.wrapper.wrap(self.iv), b''.join(self.encrypt(header + methods_bytes))]

    async def server_get_methods(self, socks_version: int, reader: asyncio.StreamReader) -> Dict[str, bool]:
        header, length, mask = await self.wrapper.cut_ws_header(reader)
        iv = await reader.readexactly(16)
        self._init_ciphers(iv)

        header, length, mask = await self.wrapper.cut_ws_header(reader)
        enc = await reader.readexactly(2)
        version, nmethods = struct.unpack("!BB", b''.join(self.decrypt(enc, wrap=False)))

        if version != socks_version:
            raise ConnectionError(f"Unsupported SOCKS version: {version}")

        encrypted_methods = await reader.readexactly(nmethods)
        methods = b''.join(self.decrypt(encrypted_methods, wrap=False))

        return {
            'supports_no_auth': 0x00 in methods,
            'supports_gss_api': 0x01 in methods,
            'supports_user_pass': 0x02 in methods
        }

    async def client_get_method(self, socks_version: int, reader: asyncio.StreamReader) -> int:
        header, length, mask = await self.wrapper.cut_ws_header(reader)
        enc = await reader.readexactly(2)
        version, method = struct.unpack("!BB", b''.join(self.decrypt(enc, wrap=False)))

        if version != socks_version:
            raise ConnectionError(f"Unsupported SOCKS version: {version}")
        if method == 0xFF:
            raise ConnectionError("No acceptable authentication methods.")

        return method

    async def server_auth_userpass(self, logins: Dict[str, str], reader: asyncio.StreamReader,
                                   writer: asyncio.StreamWriter) -> Optional[Tuple[str, str]]:
        wsh, length, mask = await self.wrapper.cut_ws_header(reader)
        encrypted_header = await reader.readexactly(2)
        auth_version, ulen = struct.unpack("!BB", b''.join(self.decrypt(encrypted_header, wrap=False)))

        wsh, length, mask = await self.wrapper.cut_ws_header(reader)
        username = await reader.readexactly(ulen)
        username = b''.join(self.decrypt(username, wrap=False)).decode()

        wsh, length, mask = await self.wrapper.cut_ws_header(reader)
        plen_encrypted = await reader.readexactly(1)
        plen = b''.join(self.decrypt(plen_encrypted, wrap=False))[0]

        wsh, length, mask = await self.wrapper.cut_ws_header(reader)
        password = await reader.readexactly(plen)
        password = b''.join(self.decrypt(password, wrap=False)).decode()

        if logins.get(username) == password:
            writer.write(b''.join(self.encrypt(struct.pack("!BB", 1, 0))))
            await writer.drain()
            return username, password
        else:
            writer.write(b''.join(self.encrypt(struct.pack("!BB", 1, 1))))
            await writer.drain()

    async def client_auth_userpass(self, username: str, password: str, reader: asyncio.StreamReader,
                                   writer: asyncio.StreamWriter) -> bool:
        username_bytes = username.encode()
        password_bytes = password.encode()

        writer.write(b''.join(self.encrypt(struct.pack("!BB", 1, len(username_bytes)))))
        writer.write(b''.join(self.encrypt(username_bytes)))
        writer.write(b''.join(self.encrypt(bytes([len(password_bytes)]))))
        writer.write(b''.join(self.encrypt(password_bytes)))
        await writer.drain()

        wsh, length, mask = await self.wrapper.cut_ws_header(reader)
        response = await reader.readexactly(2)
        version, status = struct.unpack("!BB", b''.join(self.decrypt(response, wrap=False)))

        if status != 0:
            raise ConnectionError("Authentication failed")

        return True

    async def server_handle_command(self, socks_version: int, user_command_handlers: Dict[int, Callable],
                                    reader: asyncio.StreamReader) -> Tuple[str, int, Callable]:
        header, length, mask = await self.wrapper.cut_ws_header(reader)
        raw = await reader.readexactly(4)
        version, cmd, rsv, address_type = b''.join(self.decrypt(raw, wrap=False))
        if version != socks_version:
            raise ConnectionError(f"Unsupported SOCKS version: {version}")

        if not cmd in user_command_handlers.keys():
            raise ConnectionError(f"Unsupported command: {cmd}, it must be one of {list(user_command_handlers.keys())}")
        cmd = user_command_handlers[cmd]

        match address_type:
            case 0x01:  # IPv4
                encrypted = await reader.readexactly(4 + 2)
                data = self.decrypt(encrypted, wrap=False)
                addr = '.'.join(map(str, data[:4]))
                port = int.from_bytes(data[4:], 'big')

            case 0x03:  # domain
                domain_len = int.from_bytes(b''.join(self.decrypt(await reader.readexactly(1), wrap=False)))
                data = b''.join(self.decrypt(await reader.readexactly(domain_len + 2), wrap=False))
                addr = data[:domain_len].decode()
                port = int.from_bytes(data[domain_len:], 'big')

            case 0x04:  # IPv6
                data = b''.join(self.decrypt(await reader.readexactly(16 + 2), wrap=False))
                addr = socket.inet_ntop(socket.AF_INET6, data[:16])
                port = int.from_bytes(data[16:], 'big')

            case _:
                raise ConnectionError(f"Invalid address: {address_type}, it must be 0x01/0x03/0x04")

        return addr, port, cmd

    async def client_connect_confirm(self, reader: asyncio.StreamReader) -> Tuple[str, str]:
        header, length, mask = await self.wrapper.cut_ws_header(reader)
        hdr = b''.join(self.decrypt(await reader.readexactly(4), wrap=False))
        ver, rep, rsv, atyp = hdr

        if ver != 0x05:
            raise ConnectionError(f"Invalid SOCKS version in reply: {ver}")
        if rep != 0x00:
            raise ConnectionError(f"SOCKS5 request failed, REP={rep}")

        match atyp:
            case 0x01:  # IPv4
                addr_port = b''.join(self.decrypt(await reader.readexactly(4 + 2), wrap=False))
                addr_bytes, port_bytes = addr_port[:4], addr_port[4:]
                address = socket.inet_ntoa(addr_bytes)
            case 0x03:  # Domain
                len_byte = await reader.readexactly(1)
                domain_len = b''.join(self.decrypt(len_byte, wrap=False))
                addr_port = b''.join(self.decrypt(await reader.readexactly(domain_len + 2), wrap=False))
                addr_bytes, port_bytes = addr_port[:domain_len], addr_port[domain_len:]
                address = addr_bytes.decode('idna')
            case 0x04:  # IPv6
                addr_port = b''.join(self.decrypt(await reader.readexactly(16 + 2), wrap=False))
                addr_bytes, port_bytes = addr_port[:16], addr_port[16:]
                address = socket.inet_ntop(socket.AF_INET6, addr_bytes)
            case _:
                raise ConnectionError(f"Invalid ATYP in reply: {atyp}")

        return address, struct.unpack('!H', port_bytes)[0]


    def encrypt(self, data: bytes, wrap: bool = True) -> List[bytes]:
        data = super().encrypt(data)
        if wrap:
            return [self.wrapper.wrap(frame) for frame in data]
        else:
            return data

    def decrypt(self, data: bytes, wrap: bool = True) -> List[bytes]:
        if wrap:
            data = self.wrapper.unwrap(data)
        return super().decrypt(data)


class ChaCha20_Poly1305_HTTPWS(ChaCha20_Poly1305):
    def __init__(self, *args, http_path: str = "/", ws_path: str = "/ws/", host: str = "example.com",  **kwargs):
        super().__init__(*args, **kwargs)
        self.wrapper = HTTP_WS_Wrapper(host=host, http_path=http_path, ws_path=ws_path)
        self.server_hello = self.wrapper.server_hello
        self.client_hello = self.wrapper.client_hello
        self._decoder_buffer_frame = b''

    async def server_get_methods(self, socks_version: int, reader: asyncio.StreamReader) -> Dict[str, bool]:
        wsh, length, mask = await self.wrapper.cut_ws_header(reader)
        header = await reader.readexactly(2 + self.overhead_length)
        dec = b''.join(self.decrypt(header, wrap=False))
        version, nmethods = struct.unpack("!BB", dec)

        if version != socks_version:
            raise ConnectionError(f"Unsupported SOCKS version: {version}")

        wsh, length, mask = await self.wrapper.cut_ws_header(reader)
        methods_enc = await reader.readexactly(2 + self.overhead_length)
        methods = struct.unpack(f"!{nmethods}B", b''.join(self.decrypt(methods_enc, wrap=False)))

        return {
            'supports_no_auth': 0x00 in methods,
            'supports_user_pass': 0x02 in methods
        }

    async def client_get_method(self, socks_version: int, reader: asyncio.StreamReader) -> int:
        wsh, length, mask = await self.wrapper.cut_ws_header(reader)
        enc = await reader.readexactly(2 + self.overhead_length)
        version, method = struct.unpack("!BB", b''.join(self.decrypt(enc, wrap=False)))

        if version != socks_version:
            raise ConnectionError(f"Unsupported SOCKS version: {version}")
        if method == 0xFF:
            raise ConnectionError("No acceptable authentication methods.")

        return method

    async def server_auth_userpass(self, logins: Dict[str, str], reader: asyncio.StreamReader,
                                   writer: asyncio.StreamWriter) -> Optional[Tuple[str, str]]:
        wsh, length, mask = await self.wrapper.cut_ws_header(reader)
        encrypted_header = await reader.readexactly(2 + self.overhead_length)
        auth_version, ulen = struct.unpack("!BB", b''.join(self.decrypt(encrypted_header, wrap=False)))

        wsh, length, mask = await self.wrapper.cut_ws_header(reader)
        username = await reader.readexactly(ulen + self.overhead_length)
        username = b''.join(self.decrypt(username, wrap=False)).decode()

        wsh, length, mask = await self.wrapper.cut_ws_header(reader)
        plen_encrypted = await reader.readexactly(1 + self.overhead_length)
        plen = b''.join(self.decrypt(plen_encrypted, wrap=False))[0]

        wsh, length, mask = await self.wrapper.cut_ws_header(reader)
        password = await reader.readexactly(plen + self.overhead_length)
        password = b''.join(self.decrypt(password, wrap=False)).decode()

        if logins.get(username) == password:
            writer.write(b''.join(self.encrypt(struct.pack("!BB", 1, 0))))
            await writer.drain()
            return username, password
        else:
            writer.write(b''.join(self.encrypt(struct.pack("!BB", 1, 1))))
            await writer.drain()

    async def client_auth_userpass(self, username: str, password: str, reader: asyncio.StreamReader,
                                   writer: asyncio.StreamWriter) -> bool:
        username_bytes = username.encode()
        password_bytes = password.encode()

        writer.write(b''.join(self.encrypt(struct.pack("!BB", 1, len(username_bytes)))))
        writer.write(b''.join(self.encrypt(username_bytes)))
        writer.write(b''.join(self.encrypt(bytes([len(password_bytes)]))))
        writer.write(b''.join(self.encrypt(password_bytes)))
        await writer.drain()

        wsh, length, mask = await self.wrapper.cut_ws_header(reader)
        response = await reader.readexactly(2 + self.overhead_length)
        version, status = struct.unpack("!BB", b''.join(self.decrypt(response, wrap=False)))

        if status != 0:
            raise ConnectionError("Authentication failed")

        return True

    async def server_handle_command(self, socks_version: int, user_command_handlers: Dict[int, Callable],
                                    reader: asyncio.StreamReader) -> Tuple[str, int, Callable]:

        wsh, length, mask = await self.wrapper.cut_ws_header(reader)
        first_block = await reader.readexactly(5 + self.overhead_length)
        version, cmd, rsv, address_type, address_length = b''.join(self.decrypt(first_block, wrap=False))
        if version != socks_version:
            raise ConnectionError(f"Unsupported SOCKS version: {version}")

        if not cmd in user_command_handlers.keys():
            raise ConnectionError(f"Unsupported command: {cmd}, it must be one of {list(user_command_handlers.keys())}")
        cmd = user_command_handlers[cmd]

        wsh, length, mask = await self.wrapper.cut_ws_header(reader)
        data = await reader.readexactly(address_length + self.overhead_length)
        data = b''.join(self.decrypt(data, wrap=False))
        match address_type:
            case 0x01:  # IPv4
                addr = '.'.join(map(str, data[:4]))
                port = int.from_bytes(data[4:], 'big')
            case 0x03:  # domain
                addr = data[:-2].decode()
                port = int.from_bytes(data[-2:], 'big')
            case 0x04:  # IPv6
                addr = socket.inet_ntop(socket.AF_INET6, data[:16])
                port = int.from_bytes(data[16:], 'big')
            case _:
                raise ConnectionError(f"Invalid address: {address_type}, it must be 0x01/0x03/0x04")

        return addr, port, cmd

    async def client_connect_confirm(self, reader: asyncio.StreamReader) -> Tuple[str, str]:
        wsh, length, mask = await self.wrapper.cut_ws_header(reader)
        header_encrypted = await reader.readexactly(5 + self.overhead_length)
        header = b''.join(self.decrypt(header_encrypted, wrap=False))

        ver, rep, _, address_type, address_length = header
        if ver != 0x05:
            raise ConnectionError(f"Invalid SOCKS version in reply: {ver}")
        if rep != 0x00:
            raise ConnectionError(f"SOCKS5 CONNECT failed {REPLYES[rep]}")

        wsh, length, mask = await self.wrapper.cut_ws_header(reader)
        enc = await reader.readexactly(address_length + self.overhead_length)
        data = b''.join(self.decrypt(enc, wrap=False))
        match address_type:
            case 0x01:  # IPv4
                addr = '.'.join(map(str, data[:4]))
                port = int.from_bytes(data[4:], 'big')
            case 0x03:  # domain
                addr = data[:-2].decode()
                port = int.from_bytes(data[-2:], 'big')
            case 0x04:  # IPv6
                addr = socket.inet_ntop(socket.AF_INET6, data[:16])
                port = int.from_bytes(data[16:], 'big')
            case _:
                raise ConnectionError(f"Invalid address: {address_type}, it must be 0x01/0x03/0x04")

        return addr, port


    def _parse_ws_frames(self, raw_data: bytes, buffer: bytes = b'') -> Tuple[List[bytes], bytes]:
        frames = []
        data = buffer + raw_data
        i = 0
        while i < len(data):
            if len(data) - i < 2:
                break

            byte1 = data[i]
            byte2 = data[i + 1]
            fin = (byte1 >> 7) & 1
            opcode = byte1 & 0x0F
            masked = (byte2 >> 7) & 1
            payload_len = byte2 & 0x7F
            i += 2

            if payload_len == 126:
                if len(data) - i < 2:
                    break
                payload_len = int.from_bytes(data[i:i + 2], 'big')
                i += 2
            elif payload_len == 127:
                if len(data) - i < 8:
                    break
                payload_len = int.from_bytes(data[i:i + 8], 'big')
                i += 8

            mask_key = b''
            if masked:
                if len(data) - i < 4:
                    break
                mask_key = data[i:i + 4]
                i += 4

            if len(data) - i < payload_len:
                break

            payload = data[i:i + payload_len]
            i += payload_len

            if masked:
                payload = bytes(b ^ mask_key[j % 4] for j, b in enumerate(payload))

            frames.append(payload)

        return frames, data[i:]


    def encrypt(self, data: bytes, wrap: bool = True) -> List[bytes]:
        data = super().encrypt(data)
        if wrap:
            return [self.wrapper.wrap(frame) for frame in data]
        else:
            return data

    def decrypt(self, data: bytes, wrap: bool = True) -> List[bytes]:
        if wrap:
            data_list, self._decoder_buffer_frame = self._parse_ws_frames(data, self._decoder_buffer_frame)
            return [b''.join([b''.join(super().decrypt(frame)) for frame in data_list])]

        return super().decrypt(data)

