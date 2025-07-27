from typing import *
import asyncio
import logging
import os
import struct
import socket
import time
import traceback

from .logger_setup import *
from .base_cipher import Cipher


MAX_PAYLOAD_UDP = 65535


class Socks5Server:
    def __init__(self,
                 host: str = '127.0.0.1', port: int = 1080,
                 user_white_list: Optional[Set[str]] = None,
                 users_black_list: Optional[Set[str]] = None,
                 cipher: Optional[Cipher] = None,
                 udp_cipher: Optional[Cipher] = None,
                 udp_server_timeout: int = 5*60,
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
        self.udp_server_timeout = udp_server_timeout
        self.cipher = Cipher() if cipher is None else cipher
        self.udp_cipher = Cipher() if udp_cipher is None else udp_cipher
        self.logger = logging.getLogger(__name__)

        self.cipher.is_server = True
        self.udp_cipher.is_server = True

        self.user_commands = USER_COMMANDS if user_commands is None else user_commands
        self.asyncio_server = None
        self.users = []
        self.bytes_sent = 0
        self.bytes_received = 0
        self.stop = False

    async def async_start(self):
        try:
            self.asyncio_server = await asyncio.start_server(self.handle_client, self.host, self.port)
            cip_name = self.cipher.__class__.__name__
            self.logger.info(f"SOCKS5 proxy running on {self.host}:{self.port} using cipher {cip_name}")
            async with self.asyncio_server:
                await self.asyncio_server.serve_forever()
        except KeyboardInterrupt:
            self.logger.info("Server is closed")

    def start(self):
        try:
            asyncio.run(self.async_start())
        except KeyboardInterrupt:
            self.logger.info("Server is closed")

    async def handshake(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, cipher: 'Cipher',
                        user: Optional['User'] = None) -> 'User':
        if user is None:
            client_ip, client_port = writer.get_extra_info("peername")
            user = await self.add_user(client_ip, client_port, writer)

        methods = await cipher.server_get_methods(self.socks_version, reader)

        if methods['supports_no_auth'] and self.accept_anonymous:
            logging.info(f'{user} authorizing as Anonynous')
            data = await cipher.server_send_method_to_user(self.socks_version, 0x00)
            await self.send(user, data, log_bytes=False)
        elif methods['supports_user_pass']:
            logging.info(f'{user} authorizing with username:password')
            data = await cipher.server_send_method_to_user(self.socks_version, 0x02)
            await self.send(user, data, log_bytes=False)

            auth_data = await cipher.server_auth_userpass(self.users_auth_data, reader, writer)
            if not auth_data:
                raise ConnectionError(f"Wrong authentication data {user}")

            user.username, user.password = auth_data
        else:
            data = await cipher.server_send_method_to_user(self.socks_version, 0xFF)
            await self.send(user, data, log_bytes=False)
            raise ConnectionError(f'Can not use authentication method {user}')

        user.handshaked = True
        logging.debug(f'{user} is handshaked')
        return user


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
        logging.debug(f'{user} is connecting...')
        cipher = self.cipher.copy()

        try:
            if await cipher.server_hello(self, reader, writer):
                self.logger.debug(f"Sent server_hello")
                await self.handshake(reader, writer, cipher, user=user)

                self.logger.info(f"{user} is connected")
                addr, port, command = await cipher.server_handle_command(
                    self.socks_version, self.user_commands, reader
                )
                self.logger.info(f'Client {user} sent command {command.__qualname__}')

                connection_result = await command(self, addr, port, user, cipher, reader, writer)
                self.logger.info(f'Сompleted the operation successfully, code: {connection_result}')

            else:
                self.logger.warning(f'Suspicious client connected: {user}')

        # except (ConnectionResetError, OSError):
        #     self.logger.error(f"Client {user} is disconnected")

        # except Exception as e:
        #     self.logger.error(f"Connection error: {e}")

        finally:
            await user.disconnect()

    async def pipe(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, name: str = 'default',
                   encrypt: Optional[callable] = None, decrypt: Optional[callable] = None):
        try:
            while not reader.at_eof():
                data = await reader.read(4096)
                if not data:
                    break
                if self.log_bytes:
                    self.bytes_received += len(data)

                if decrypt:
                    data = decrypt(data)
                if encrypt:
                    data = encrypt(data)

                writer.write(data)
                if self.log_bytes:
                    self.bytes_sent += len(data)
                await writer.drain()
        except Exception as e:
            self.logger.error(f"Proxying PIPE '{name}' error: {e}")
            traceback.print_stack(e)
        finally:
            writer.close()
            await writer.wait_closed()

    async def send(self, user: 'User', data: bytes, log_bytes: bool = True):
        user.writer.write(data)
        if self.log_bytes and log_bytes:
            self.bytes_sent += len(data)
        await user.writer.drain()
        self.logger.debug(f'Sent {len(data)} bytes to {user}')

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
        self.stop = True
        self.logger.info("Shutting down TCP server...")
        self.asyncio_server.close()
        await self.asyncio_server.wait_closed()
        self.logger.info("Server is closed")

    def close(self):
        self._loop.run_until_complete(self.async_close())
        self._loop.stop()
        self._loop.close()


    async def __aenter__(self):
        self.asyncio_server = await asyncio.start_server(self.handle_client, self.host, self.port)
        cip_name = self.cipher.__class__.__name__
        self.logger.info(f"SOCKS5 proxy running on {self.host}:{self.port} using cipher {cip_name}")
        return self
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.async_close()

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


class UDPServerProxy(asyncio.DatagramProtocol):
    def __init__(self, tcp_server: Socks5Server):
        self.tcp_server = tcp_server
        self.cipher = self.tcp_server.udp_cipher.copy()
        self.logger = self.tcp_server.logger
        self.timeout = self.tcp_server.udp_server_timeout

        self.last_activity = time.time()
        self.fragment_buffer = {}
        self.host = None
        self.port = None
        self.client_addr: Optional[Tuple[str, int]] = None
        self.transport = None
        self.stop = False

    def connection_made(self, transport):
        self.transport = transport
        self.host, self.port = transport.get_extra_info('sockname')
        self.last_activity = time.time()
        self.logger.debug(f"{self} started")
        asyncio.create_task(self.monitor_timeout())

    async def monitor_timeout(self):
        while not self.stop:
            await asyncio.sleep(1)
            if time.time() - self.last_activity > self.timeout:
                self.logger.debug(f"{self} timeout reached. Closing...")
                self.transport.close()
                self.stop = True

    def datagram_received(self, data: bytes, addr: Tuple[str, int]):
        self.last_activity = time.time()
        self.logger.debug(f"UDP packet received from {addr}")

        try:
            if self.client_addr is None:
                self.client_addr = addr

            if len(data) <= MAX_PAYLOAD_UDP:
                if addr == self.client_addr:
                    self.handle_client(data, addr)
                else:
                    self.handle_remote(data, addr)

        except Exception as ex:
            self.logger.error(f'UDP server error, shutting down...')
            self.transport.close()

    def handle_client(self, data: bytes, addr: Tuple[str, int]):
        try:
            data = self.cipher.decrypt(data)
            if len(data) < 4:
                self.logger.warning("UDP packet too short for SOCKS5 header.")
                return

            rsv, frag, atyp = struct.unpack("!HBB", data[:4])

            offset = 4
            if atyp == 0x01:  # IPv4
                if len(data) < offset + 4 + 2:
                    self.logger.warning("Truncated IPv4 header in UDP packet.")
                    return
                dst_addr = socket.inet_ntoa(data[offset:offset + 4])
                offset += 4

            elif atyp == 0x03:  # Domain
                if len(data) < offset + 1:
                    self.logger.warning("Truncated domain length in UDP packet.")
                    return
                domain_len = data[offset]
                offset += 1
                if len(data) < offset + domain_len + 2:
                    self.logger.warning("Truncated domain in UDP packet.")
                    return
                dst_addr = data[offset:offset + domain_len].decode(errors="replace")
                offset += domain_len

            elif atyp == 0x04:  # IPv6
                if len(data) < offset + 16 + 2:
                    self.logger.warning("Truncated IPv6 header in UDP packet.")
                    return
                dst_addr = socket.inet_ntop(socket.AF_INET6, data[offset:offset + 16])
                offset += 16

            else:
                self.logger.warning(f"Unknown ATYP={atyp} in UDP packet.")
                return

            dst_port = struct.unpack("!H", data[offset:offset + 2])[0]
            offset += 2

            payload = data[offset:]
            self.logger.debug(f"Client->Remote UDP: {len(payload)} bytes to {dst_addr}:{dst_port}")

            if atyp == 0x03:
                try:
                    infos = socket.getaddrinfo(dst_addr, dst_port, type=socket.SOCK_DGRAM)
                    for fam, *_rest, sockaddr in infos:
                        if fam in (socket.AF_INET, socket.AF_INET6):
                            dst_addr = sockaddr[0]
                            dst_port = sockaddr[1]
                            break
                except Exception as e:
                    self.logger.warning(f"DNS resolve failed for {dst_addr}: {e}")
                    return

            if 0 < frag < 128:
                self.fragment_buffer[frag] = payload
            elif frag == 0:
                keys = list(sorted(self.fragment_buffer.keys()))
                if self.fragment_buffer:
                    if keys == list(range(keys[0], keys[-1]+1)):
                        payload = b''.join(self.fragment_buffer[i] for i in keys) + payload
                    else:
                        self.logger.warning(f"Lost some packet from fragments, fragments was ignored")

                self.fragment_buffer = {}

                try:
                    self.transport.sendto(payload, (dst_addr, dst_port))
                except Exception as e:
                    self.logger.error(f"UDP sendto failed {dst_addr}:{dst_port}: {e}")

        except Exception as e:
            self.logger.error(f"Failed to parse client UDP packet: {e}")

    def handle_remote(self, payload: bytes, addr: Tuple[str, int]):
        remote_ip, remote_port = addr
        self.logger.debug(f"Remote->Client UDP: {len(payload)} bytes from {remote_ip}:{remote_port}")

        try:
            ip_obj = None
            atyp = 0x01
            addr_bytes = b""
            try:
                ip_obj = socket.inet_pton(socket.AF_INET, remote_ip)
                atyp = 0x01
                addr_bytes = ip_obj
            except OSError:
                try:
                    ip_obj6 = socket.inet_pton(socket.AF_INET6, remote_ip)
                    atyp = 0x04
                    addr_bytes = ip_obj6
                except OSError:
                    atyp = 0x03
                    dom = remote_ip.encode("idna")
                    if len(dom) > 255:
                        dom = dom[:255]
                    addr_bytes = bytes([len(dom)]) + dom

            if atyp == 0x01:
                header = struct.pack("!HBB4sH", 0, 0, atyp, addr_bytes, remote_port)
            elif atyp == 0x04:
                header = struct.pack("!HBB16sH", 0, 0, atyp, addr_bytes, remote_port)
            else:  # domain
                header = struct.pack("!HBB", 0, 0, atyp) + addr_bytes + struct.pack("!H", remote_port)

            packet = header + payload

            if self.client_addr:
                self.transport.sendto(self.cipher.encrypt(packet), self.client_addr)

        except Exception as e:
            self.logger.error(f"Failed to build SOCKS5 UDP reply: {e}")

    def error_received(self, exc):
        self.logger.error(f"Error received: {exc}")

    def connection_lost(self, exc):
        self.stop = True
        self.logger.info(f"{self} transport closed: {exc}")

    def __str__(self):
        host_port = f"{self.host}:{self.port}, " if self.host and self.port else ""
        return f'{self.__class__.__name__}({host_port}cipher={self.cipher})'


class ConnectionMethods:
    @staticmethod
    async def CONNECT(server: Socks5Server, addr: str, port: int, user: User, cipher: Cipher,
                             client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter) -> int:
        server.logger.debug(f"Establishing TCP connection for {user} to {addr}:{port}...")

        try:
            remote_reader, remote_writer = await asyncio.open_connection(addr, port)
            local_ip, local_port = remote_writer.get_extra_info("sockname")
            client_writer.write(await cipher.server_make_reply(server.socks_version, 0x00, local_ip, local_port))
            await client_writer.drain()
        except Exception as e:
            server.logger.warning(f"Failed to connect to {addr}:{port} => {e}")
            client_writer.write(await cipher.server_make_reply(server.socks_version, 0xFF, '0.0.0.0', 0))
            await client_writer.drain()
            return 1

        server.logger.debug(f'{user} connected to {addr}:{port}')
        # try:
        await asyncio.gather(
            server.pipe(client_reader, remote_writer, decrypt=cipher.decrypt, name='client -> server'),
            server.pipe(remote_reader, client_writer, encrypt=cipher.encrypt, name='client <- servers'),
        )
        # except (ConnectionResetError, OSError):
        #     pass
        server.logger.debug(f"TCP connection to {addr}:{port} is closed")
        return 0

    @staticmethod
    async def BIND(server: Socks5Server, addr: str, port: int, user: User, cipher: Cipher,
                          client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter) -> int:
        server.logger.error(f"bind_socket {addr}:{port}")
        return 0

    @staticmethod
    async def UDP_ASSOCIATE(server: Socks5Server, addr: str, port: int, user: User, cipher: Cipher,
                             client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter) -> int:
        server.logger.debug("Starting UDP server...")
        loop = asyncio.get_running_loop()

        try:
            transport, protocol = await loop.create_datagram_endpoint(
                lambda: UDPServerProxy(server),
                local_addr=('0.0.0.0', 0)
            )
        except Exception as e:
            server.logger.error(f"Failed to start UDP relay: {e}")
            reply = await cipher.server_make_reply(server.socks_version, 0x01, '0.0.0.0', 0)
            client_writer.write(reply)
            await client_writer.drain()
            return 1

        udp_host, udp_port = transport.get_extra_info('sockname')
        udp_host = '127.0.0.1' if udp_host == '0.0.0.0' else udp_host
        server.logger.info(f"Started UDP server for {addr}:{port} at {udp_host}:{udp_port}")

        try:
            reply = await cipher.server_make_reply(server.socks_version, 0x00, udp_host, udp_port)
            client_writer.write(reply)
            await client_writer.drain()
        except Exception as e:
            self.logger.warning(f"Failed to make UDP connection at TCP {addr}:{port}; UDP {udp_host}:{udp_port} => {e}")
            client_writer.write(await default_cipher.server_make_reply(self.socks_version, 0xFF, '0.0.0.0', 0))
            await client_writer.drain()
            return

        try:
            while True:
                try:
                    if server.stop:
                        server.logger.debug("Server stopping: closing UDP assoc.")
                        break
                    if not user.connected:
                        server.logger.debug("User disconnected: closing UDP assoc.")
                        break

                    if client_reader.at_eof():
                        server.logger.debug("TCP reader EOF: closing UDP assoc.")
                        break
                    if client_writer.is_closing():
                        server.logger.debug("TCP writer closing: closing UDP assoc.")
                        break

                    await asyncio.sleep(.5)
                except Exception as e:
                    server.logger.warning(f"UDP_ASSOCIATE TCP connection error: {e}")
                    break
        finally:
            transport.close()

        return 0


USER_COMMANDS = {
    0x01: ConnectionMethods.CONNECT,
    0x02: ConnectionMethods.BIND,
    0x03: ConnectionMethods.UDP_ASSOCIATE,
}