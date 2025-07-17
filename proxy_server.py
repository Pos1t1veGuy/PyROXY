from typing import *
import asyncio
import logging
import os

import logger_setup
from base_cipher import Cipher


class Socks5Server:
    def __init__(self,
                 host: str = '127.0.0.1', port: int = 1080,
                 user_white_list: Optional[Set[str]] = None,
                 users_black_list: Optional[Set[str]] = None,
                 cipher: Optional[Cipher] = None,
                 users: Optional[Dict[str, str]] = None,
                 user_commands: Optional[Dict[bytes, callable]] = None,
                 accept_anonymous: bool = False,
                 log_bytes: bool = True):

        self.socks_version = 5
        self.accept_anonymous = accept_anonymous
        self.users_auth_data = users if not users is None else {}
        self.host = host
        self.port = port
        self.user_white_list = user_white_list
        self.users_black_list = users_black_list
        self.log_bytes = log_bytes # only after handshake
        self.cipher = Cipher if cipher is None else cipher
        self.logger = logging.getLogger(__name__)

        self.user_commands = USER_COMMANDS if user_commands is None else user_commands
        self.asyncio_server = None
        self.users = []
        self.bytes_sent = 0
        self.bytes_received = 0

    async def async_start(self):
        try:
            self.asyncio_server = await asyncio.start_server(self.handle_client, self.host, self.port)
            self.logger.info(f"SOCKS5 proxy running on {self.host}:{self.port}")
            async with self.asyncio_server:
                await self.asyncio_server.serve_forever()
        except KeyboardInterrupt:
            self.logger.info("Server is closed")

    def start(self):
        try:
            asyncio.run(self.async_start())
        except KeyboardInterrupt:
            self.logger.info("Server is closed")

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        client_ip, client_port = writer.get_extra_info("peername")
        if not self.users_black_list is None:
            if client_ip in self.users_black_list:
                self.logger.warning(f"Blocked connection from blacklisted IP: {client_ip}")
                return
        if not self.user_white_list is None:
            if not client_ip in self.user_white_list:
                self.logger.warning(f"Blocked connection from non-whitelisted IP: {client_ip}")
                return
        user = await self.add_user(client_ip, client_port, writer)

        try:
            methods = await self.cipher.server_get_methods(self.socks_version, reader)

            if methods['supports_user_pass']:
                data = await self.cipher.server_send_method_to_user(self.socks_version, 0x02)
                await self.send(writer, data, log_bytes=False)

                auth_ok = await self.cipher.server_auth_userpass(self.users_auth_data, reader, writer)
                if not auth_ok:
                    self.logger.warning(f"Authentication failed {client_ip}:{client_port}")
                    return
            elif methods['supports_no_auth'] and self.accept_anonymous:
                data = await self.cipher.server_send_method_to_user(self.socks_version, 0x00)
                await self.send(writer, data, log_bytes=False)
            else:
                data = await self.cipher.server_send_method_to_user(self.socks_version, 0xFF)
                await self.send(writer, data, log_bytes=False)
                return

            user.handshaked = True

            addr, port, command = await self.cipher.server_handle_command(
                self.socks_version, self.user_commands, reader
            )

            connection_result = await command(self, addr, port, reader, writer)
            self.logger.info(f'Сompleted the operation successfully, code: {connection_result}')

        except Exception as e:
            self.logger.error(f"Connection error: {e}")

        finally:
            await user.disconnect()

    async def pipe(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                   encrypt: Optional[callable] = None, decrypt: Optional[callable] = None):
        try:
            while not reader.at_eof():
                data = await reader.read(4096)
                if not data:
                    break
                if self.log_bytes:
                    self.bytes_received += len(data)

                if decrypt:
                    data = await decrypt(data)
                if encrypt:
                    data = await encrypt(data)

                await self.send(writer, data)
        except Exception as e:
            self.logger.error(f"Proxying error: {e}")
        finally:
            writer.close()
            await writer.wait_closed()

    async def send(self, writer: asyncio.StreamWriter, data: bytes, log_bytes: bool = True):
        writer.write(data)
        if self.log_bytes and log_bytes:
            self.bytes_sent += len(data)
        await writer.drain()

    async def add_user(self, client_ip: str, client_port: int, writer: asyncio.StreamWriter) -> 'User':
        user = User(self, client_ip, client_port, writer=writer)
        self.users.append(user)
        user.id = self.users.index(user)
        return user

    async def delete_user(self, user: 'User'):
        if user in self.users:
            self.users.remove(user)

    async def ban_user(self, user: 'User'):
        self.users_black_list.append(user.ip)
        await user.disconnect_user()
        self.logger.info(f'User {user} is banned')

    async def disconnect_user(self, user: 'User'):
        if user.connected:
            user.connected = False
            user.writer.close()
            await user.writer.wait_closed()
        await self.delete_user(user)
        self.logger.info(f'{user} is disconnected')

    async def async_close(self):
        self.logger.info("Shutting down server...")
        self.asyncio_server.close()
        await self.asyncio_server.wait_closed()
        self.logger.info("Server is closed")

    def close(self):
        self._loop.run_until_complete(self.async_close())
        self._loop.stop()
        self._loop.close()


    async def __aenter__(self):
        self.asyncio_server = await asyncio.start_server(self.handle_client, self.host, self.port)
        self.logger.info(f"SOCKS5 proxy running on {self.host}:{self.port}")
        return self
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.async_close()

    def __enter__(self):
        self.start()
        return self
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def __str__(self):
        return f'{self.__class__.__name__}(host="{self.host}", port={self.port}, cipher={self.cipher})'


class User:
    def __init__(self, server: Socks5Server, ip: str, port: int, writer: asyncio.StreamWriter, id: Optional[int] = None,
                 handshaked: bool = False, username: str = 'Anonymous', password: Optional[str] = None):
        self.server = server
        self.id = id
        self.ip = ip
        self.port = port
        self.writer = writer

        self.handshaked = handshaked
        self.username = username
        self.password = password

        self.connected = True

    @property
    def is_anonymous(self) -> bool:
        return self.username == 'Anonymous' and self.password is None

    async def disconnect(self):
        await self.server.disconnect_user(self)

    async def ban(self):
        await self.server.ban_user(self)

    def __str__(self):
        address = f'"{self.ip}:{self.port}"'
        return f'{self.__class__.__name__}("{self.username}", id={self.id}, handshaked={self.handshaked}, address={address})'


class Socks5UDPServer:
    def __init__(self, tcp_server: Socks5Server, client_writer: asyncio.StreamWriter):
        self.tcp_server = tcp_server
        self.client_writer = client_writer
        self.logger = self.tcp_server.logger
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport
        self.logger.info(f"UDP server started on {transport.get_extra_info('sockname')}")

    def datagram_received(self, data, addr):
        print(f"Received {len(data)} bytes from {addr}")
        # TODO: Распарсить SOCKS5 UDP header, достать DST.ADDR/DST.PORT и данные
        # TODO: Переслать данные на целевой хост через asyncio.open_connection (TCP) или asyncio Datagram
        # TODO: Ответы завернуть в SOCKS5 UDP Response Header и отправить обратно self.transport.sendto(...)

    def error_received(self, exc):
        self.logger.error(f"Error received: {exc}")

    def connection_lost(self, exc):
        self.logger.info("UDP server closed")


class ConnectionMethods:
    @staticmethod
    async def CONNECT(server: Socks5Server, addr: str, port: int,
                             client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter) -> int:
        server.logger.info(f"Establishing TCP connection to {addr}:{port}...")

        try:
            remote_reader, remote_writer = await asyncio.open_connection(addr, port)
            local_ip, local_port = remote_writer.get_extra_info("sockname")
            client_writer.write(await server.cipher.server_make_reply(server.socks_version, 0x00, local_ip, local_port))
            await client_writer.drain()
        except Exception as e:
            server.logger.warning(f"Failed to connect to {addr}:{port} => {e}")
            client_writer.write(await server.cipher.server_make_reply(server.socks_version, 0xFF, '0.0.0.0', 0))
            await client_writer.drain()
            return 1

        await asyncio.gather(
            server.pipe(client_reader, remote_writer, decrypt=server.cipher.decrypt), # client -> server
            server.pipe(remote_reader, client_writer, encrypt=server.cipher.encrypt), # client <- servers
        )
        server.logger.info(f"TCP connection to {addr}:{port} is closed")
        return 0

    @staticmethod
    async def BIND(server: Socks5Server, addr: str, port: int,
                          client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter) -> int:
        server.logger.info(f"bind_socket {addr}:{port}")
        return 0

    @staticmethod
    async def UDP_ASSOCIATE(server: Socks5Server, addr: str, port: int,
                             client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter) -> int:
        server.logger.info(f"Starting UDP server for {addr}:{port}")
        loop = asyncio.get_running_loop()

        transport, protocol = await loop.create_datagram_endpoint(
            lambda: UDPServerProxy(server, client_writer),
            local_addr=('0.0.0.0', 0) # 0 - random OS port
        )
        udp_host, udp_port = transport.get_extra_info('sockname')

        server.logger.info(f"UDP server listening on {udp_host}:{udp_port}")

        reply = await server.cipher.server_make_reply(server.socks_version, 0x00, udp_host, udp_port)
        client_writer.write(reply)
        await client_writer.drain()

        try:
            await client_reader.read() # Waiting for TCP connection close
        except Exception as e:
            server.logger.warning(f"UDP_ASSOCIATE TCP connection error: {e}")
        finally:
            transport.close()
            server.logger.info("UDP server closed")

        return 0


USER_COMMANDS = {
    0x01: ConnectionMethods.CONNECT,
    0x02: ConnectionMethods.BIND,
    0x03: ConnectionMethods.UDP_ASSOCIATE,
}