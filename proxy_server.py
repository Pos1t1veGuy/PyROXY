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
                 user_commands: Optional[Dict[bytes, callable]] = None,
                 users: Optional[Dict[str, str]] = None,
                 accept_anonymous: bool = False,
                 log_bytes: bool = True):

        self.socks_version = 5
        self.accept_anonymous = accept_anonymous
        self.users = users if not users is None else {}
        self.host = host
        self.port = port
        self.user_white_list = user_white_list
        self.users_black_list = users_black_list
        self.log_bytes = log_bytes # only after handshake
        self.cipher = Cipher if cipher is None else cipher
        self.logger = logging.getLogger(__name__)

        self.user_commands_default = {
            0x01: ConnectionMethods.tcp_connection,
            0x03: ConnectionMethods.bind_socket,
            0x04: ConnectionMethods.udp_connection,
        }
        self.user_commands = self.user_commands_default if user_commands is None else user_commands
        self.asyncio_server = None
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
        try:
            client_ip, client_port = writer.get_extra_info("peername")
            if not self.users_black_list is None:
                if client_ip in self.users_black_list:
                    self.logger.warning(f"Blocked connection from blacklisted IP: {client_ip}")
                    return
            if not self.user_white_list is None:
                if not client_ip in self.user_white_list:
                    self.logger.warning(f"Blocked connection from non-whitelisted IP: {client_ip}")
                    return

            methods = await self.cipher.server_get_methods(self.socks_version, reader)

            if methods['supports_user_pass']:
                data = await self.cipher.server_send_method_to_user(self.socks_version, 0x02)
                await self.send(writer, data, log_bytes=False)

                auth_ok = await self.cipher.server_auth_userpass(self.users, reader, writer)
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

            addr, port, command = await self.cipher.server_handle_command(
                self.socks_version, self.user_commands, reader
            )

            connection_result = await command(self, addr, port, reader, writer)
            self.logger.info(f'Сompleted the operation successfully, code: {connection_result}')

        except Exception as e:
            self.logger.error(f"Connection error: {e}")

        finally:
            writer.close()
            await writer.wait_closed()

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


class ConnectionMethods:
    @staticmethod
    async def tcp_connection(server: Socks5Server, addr: str, port: int,
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
    async def bind_socket(server: Socks5Server, addr: str, port: int,
                          client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter) -> int:
        server.logger.info(f"bind_socket {addr}:{port}")
        return 0

    @staticmethod
    async def udp_connection(server: Socks5Server, addr: str, port: int,
                             client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter) -> int:
        server.logger.info(f"udp_connection {addr}:{port}")
        return 0


if __name__ == '__main__':
    import hashlib
    from ext.ciphers import AESCipherCTR
    key = hashlib.sha256(b'my master key').digest()
    SERVER = Socks5Server(users={
        "u1": "pw1",
    }, cipher=AESCipherCTR(key))
    SERVER.start() # Доделать интеграцию с БД; Сделать пару шифраторов