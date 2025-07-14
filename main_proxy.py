from typing import *
import struct
import asyncio
import socket
import ipaddress as ipa
import logging

logging.basicConfig(
    level=logging.INFO,
    format='{%(asctime)s} [%(levelname)s] %(message)s',
    datefmt='%H:%M:%S'
)

logger = logging.getLogger(__name__)


class Socks5Server:
    def __init__(self,
                 host: str = '127.0.0.1', port: int = 1080,
                 user_white_list: Optional[Set[str]] = None,
                 users_black_list: Optional[Set[str]] = None,
                 user_commands: Optional[Dict[bytes, callable]] = None,
                 users: Optional[Dict[str, str]] = None,
                 accept_anonymous: bool = False):

        self.socks_version = 5
        self.accept_anonymous = accept_anonymous
        self.users = users if not users is None else {}
        self.host = host
        self.port = port
        self.user_white_list = user_white_list
        self.users_black_list = users_black_list

        self.user_commands_default = {
            0x01: ConnectionMethods.tcp_connection,
            0x03: ConnectionMethods.bind_socket,
            0x04: ConnectionMethods.udp_connection,
        }
        self.user_commands = {} if user_commands is None else self.user_commands_default
        self.asyncio_server = None

    async def async_start(self):
        try:
            self.asyncio_server = await asyncio.start_server(self.handle_client, self.host, self.port)
            logger.info(f"SOCKS5 proxy running on {self.host}:{self.port}")
            async with self.asyncio_server:
                await self.asyncio_server.serve_forever()
        except KeyboardInterrupt:
            logger.info("Server is closed")

    def start(self):
        try:
            asyncio.run(self.async_start())
        except KeyboardInterrupt:
            logger.info("Server is closed")

    async def handle_client(self, reader, writer):
        try:
            client_ip, client_port = writer.get_extra_info("peername")
            if not self.users_black_list is None:
                if client_ip in self.users_black_list:
                    logger.warning(f"Blocked connection from blacklisted IP: {client_ip}")
                    return
            if not self.user_white_list is None:
                if not client_ip in self.user_white_list:
                    logger.warning(f"Blocked connection from non-whitelisted IP: {client_ip}")
                    return

            socks_version, nmethods = await reader.readexactly(2)
            if socks_version != self.socks_version:
                logger.error(f"Unsupported SOCKS version: {socks_version}")
                return

            methods = await reader.readexactly(nmethods)

            supports_no_auth = 0x00 in methods
            supports_user_pass = 0x02 in methods

            if supports_user_pass:
                writer.write(bytes([self.socks_version, 0x02]))
                await writer.drain()
                auth_ok = await self.auth_userpass(reader, writer)
                if not auth_ok:
                    logger.warning(f"Authentication failed {client_ip}:{client_port}")
                    return
            elif supports_no_auth and self.accept_anonymous:
                writer.write(bytes([self.socks_version, 0x00]))
                await writer.drain()
            else:
                writer.write(bytes([self.socks_version, 0xFF]))
                await writer.drain()
                return

            addr, port, command = await self.handle_command(reader, writer)

            connection_result = await command(self, addr, port, reader, writer)
            logger.info(f'Сompleted the operation successfully, code: {connection_result}')

        except Exception as e:
            logger.error(f"Connection error: {e}")

        finally:
            writer.close()
            await writer.wait_closed()


    async def handle_command(self, reader, writer) -> Tuple[str, int, callable]:
        socks_version, cmd, rsv, address_type = await reader.readexactly(4)
        if socks_version != self.socks_version:
            raise ConnectionError(f"Unsupported SOCKS version: {socks_version}")

        if not cmd in self.user_commands.keys():
            raise ConnectionError(f"Unsupported command: {cmd}, it must be one of {list(self.user_commands.keys())}")
        cmd = self.user_commands[cmd]

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

    async def auth_userpass(self, reader, writer) -> bool:
        auth_version = (await reader.readexactly(1))[0]

        if auth_version == 1:
            username_length = (await reader.readexactly(1))[0]
            username = (await reader.readexactly(username_length)).decode()

            pw_length = (await reader.readexactly(1))[0]
            pw = (await reader.readexactly(pw_length)).decode()

            logger.info(f"Auth attempt: {username=} {pw=}")

            if self.users.get(username) == pw:
                writer.write(bytes([1, 0]))
                await writer.drain()
                return True
            else:
                writer.write(bytes([1, 1]))
                await writer.drain()

        else:
            logger.warning(f"Invalid auth version: {auth_version}")

        return False

    async def make_reply(self, reply_code: int, address: str = '0', port: int = 0) -> bytes:
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
            self.socks_version,
            reply_code,
            0x00,  # RSV
            address_type,
            addr_data,
            port
        )

    @staticmethod
    async def pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        try:
            while not reader.at_eof():
                data = await reader.read(4096)
                if not data:
                    break
                writer.write(data)
                await writer.drain()
        except Exception as e:
            logger.error(f"Proxying error: {e}")
        finally:
            writer.close()
            await writer.wait_closed()


class ConnectionMethods:
    @staticmethod
    async def tcp_connection(server: Socks5Server, addr: str, port: int,
                             client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter) -> int:
        logger.info(f"Establishing TCP connection to {addr}:{port}...")

        try:
            remote_reader, remote_writer = await asyncio.open_connection(addr, port)
            local_ip, local_port = remote_writer.get_extra_info("sockname")
            client_writer.write(await server.make_reply(0x00, local_ip, local_port))
            await client_writer.drain()
        except Exception as e:
            logger.warning(f"Failed to connect to {addr}:{port} => {e}")
            client_writer.write(await server.make_reply(0xFF, '0.0.0.0', 0))
            await client_writer.drain()
            return 1

        await asyncio.gather(
            server.pipe(client_reader, remote_writer),
            server.pipe(remote_reader, client_writer)
        )

        logger.info(f"TCP connection to {addr}:{port} is closed")
        return 0

    @staticmethod
    async def bind_socket(server: Socks5Server, addr: str, port: int,
                          client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter) -> int:
        logger.info(f"bind_socket {addr}:{port}")
        return 0

    @staticmethod
    async def udp_connection(server: Socks5Server, addr: str, port: int,
                             client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter) -> int:
        logger.info(f"udp_connection {addr}:{port}")
        return 0


if __name__ == '__main__':
    SERVER = Socks5Server(users={
        "u1": "pw1",
    })
    SERVER.start()