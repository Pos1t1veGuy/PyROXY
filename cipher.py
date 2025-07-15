from typing import *
import socket
import struct
import asyncio
import ipaddress as ipa
from logger_setup import logger


'''
To establish a SOCKS5 connection, the client and server must complete a handshake consisting of 4–5 steps:

1. get_methods – The server receives a list of supported authentication methods from the client.
   This method must return: {'supports_no_auth': bool, 'supports_user_pass': bool}.
2. auth_userpass (*) – If the client wants to authenticate, the server checks whether the client
   exists in the user dictionary.
3. send_method_to_user – The server selects an authentication method (no_auth/auth = 0x00/0x02)
   and informs the client.
4. handle_command – The server receives a client command (CONNECT/BIND/UDP_ASSOCIATE = 0x01/0x03/0x04),
   extracts the destination address and port, and determines the handler method.
5. make_reply – This final step confirms the SOCKS5 connection. It sends a reply indicating
   whether the connection was successfully established.

If the connection is successful, data exchange begins using the 'encrypt' and 'decrypt' methods.
'''


class Cipher:
    def __init__(self):
        ...

    async def get_methods(self, socks_version: int, reader: asyncio.StreamReader,
                          writer: asyncio.StreamWriter) -> Dict[str, bool]:
        return {}

    async def auth_userpass(self, logins: Dict[str, str], reader: asyncio.StreamReader,
                            writer: asyncio.StreamWriter) -> bool:
        return False

    async def send_method_to_user(self, socks_version: int, method: int, reader: asyncio.StreamReader,
                                  writer: asyncio.StreamWriter) -> None:
        return None

    async def handle_command(self, socks_version: int, user_command_handlers: Dict[int, Callable],
                             reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> Tuple[str, int, Callable]:
        return '', 0, lambda: 0

    async def make_reply(self, socks_version: int, reply_code: int, address: str = '0', port: int = 0) -> bytes:
        return b''

    async def encrypt(self, data: bytes) -> bytes:
        return b''

    async def decrypt(self, data: bytes) -> bytes:
        return b''


class DefaultCipher(Cipher):
    def __init__(self):
        super().__init__()

    async def get_methods(self, socks_version: int, reader: asyncio.StreamReader,
                          writer: asyncio.StreamWriter) -> Dict[str, bool]:
        version, nmethods = await reader.readexactly(2)
        if version != socks_version:
            logger.error(f"Unsupported SOCKS version: {version}")
            raise ConnectionError(f"Unsupported SOCKS version: {version}")

        methods = await reader.readexactly(nmethods)

        return {
            'supports_no_auth': 0x00 in methods,
            'supports_user_pass': 0x02 in methods
        }

    async def auth_userpass(self, logins: Dict[str, str], reader: asyncio.StreamReader,
                            writer: asyncio.StreamWriter) -> bool:
        auth_version = (await reader.readexactly(1))[0]

        if auth_version == 1:
            username_length = (await reader.readexactly(1))[0]
            username = (await reader.readexactly(username_length)).decode()

            pw_length = (await reader.readexactly(1))[0]
            pw = (await reader.readexactly(pw_length)).decode()

            logger.info(f"Auth attempt: {username=} {pw=}")

            if logins.get(username) == pw:
                writer.write(bytes([1, 0]))
                await writer.drain()
                return True
            else:
                writer.write(bytes([1, 1]))
                await writer.drain()

        else:
            logger.warning(f"Invalid auth version: {auth_version}")

        return False

    async def send_method_to_user(self, socks_version: int, method: int, reader: asyncio.StreamReader,
                                  writer: asyncio.StreamWriter) -> None:
        writer.write(bytes([socks_version, method]))
        await writer.drain()

    async def handle_command(self, socks_version: int, user_command_handlers: Dict[int, Callable],
                             reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> Tuple[str, int, Callable]:

        version, cmd, rsv, address_type = await reader.readexactly(4)
        if version != socks_version:
            raise ConnectionError(f"Unsupported SOCKS version: {version}")

        if not cmd in user_command_handlers.keys():
            raise ConnectionError(f"Unsupported command: {cmd}, it must be one of {list(user_command_handlers.keys())}")
        cmd = user_command_handlers[cmd]

        match address_type:
            case 0x01: # IPv4
                addr_bytes = await reader.readexactly(4)
                addr = '.'.join(map(str, addr_bytes))
            case 0x03: # domain
                domain_length = (await reader.readexactly(1))[0]
                domain_bytes = await reader.readexactly(domain_length)
                addr = domain_bytes.decode()
            case 0x04: # IPv6
                addr_bytes = await reader.readexactly(16)
                addr = socket.inet_ntop(socket.AF_INET6, addr_bytes)
            case _:
                raise ConnectionError(f"Invalid address: {address_type}, it must be 0x01/0x03/0x04")

        port_bytes = await reader.readexactly(2)
        port = int.from_bytes(port_bytes, byteorder='big')
        return addr, port, cmd

    async def make_reply(self, socks_version: int, reply_code: int, address: str = '0', port: int = 0) -> bytes:
        address_type = 0x01
        head = "!BBBB"
        addr_data = socket.inet_aton("0.0.0.0")
        tail = "4sH"

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
            tail = f"{1 + len(addr_bytes)}sH"

        except:
            address_type = 0x01
            port = 0

        return struct.pack(
            head + tail,
            socks_version,
            reply_code,
            0x00,  # RSV
            address_type,
            addr_data,
            port
        )

    async def encrypt(self, data: bytes) -> bytes:
        return data

    async def decrypt(self, data: bytes) -> bytes:
        return data