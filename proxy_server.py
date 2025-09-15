from typing import *
import asyncio
import logging
import os
import struct
import socket
import time
from collections import deque

from .logger_setup import *
from .base_cipher import Cipher, REPLYES_CODES, get_address, resolve_domain, encode_ip
from .db_handlers import SQLite_Handler


MAX_PAYLOAD_UDP = 65535
SHORT_PERIOD_OF_TIME = 10 # sec
CONN_ALIVE_MAX_NUMS = 50
CONNCETIONS_THRESHOLD = 100


class Socks5Server:
    def __init__(self,
                 host: str = '127.0.0.1', port: int = 1080,
                 user_white_list: Optional[Set[str]] = None,
                 users_black_list: Optional[Set[str]] = None,
                 ciphers: List[Cipher] = [Cipher()],
                 udp_cipher: Optional[Cipher] = None,
                 udp_server_timeout: int = 5*60,
                 db_handler: Optional['Handler'] = None,
                 user_commands: Optional[Dict[bytes, callable]] = None,
                 accept_anonymous: bool = False,
                 log_bytes: bool = True,
                 address_changing: bool = True):

        self.socks_version = 5
        self.accept_anonymous = accept_anonymous
        self.address_changing = address_changing
        self.host = host
        self.port = port
        self.user_white_list = user_white_list
        self.users_black_list = users_black_list
        self.log_bytes = log_bytes # only after handshake
        self.udp_server_timeout = udp_server_timeout
        self.ciphers = ciphers
        self.db_handler = db_handler
        self.udp_cipher = Cipher() if udp_cipher is None else udp_cipher
        self.logger = logging.getLogger(__name__)

        self.clients_tcp_timestamps: Dict[str, deque[int]] = {}
        # self.clients_udp_timestamps: Dict[str, deque[int]] = {}

        self.clients_tcp_alive_time: Dict[str, deque[int]] = {}
        # self.clients_udp_alive_time: Dict[str, deque[int]] = {}

        for cipher in self.ciphers:
            cipher.is_server = True
        self.udp_cipher.is_server = True

        self.user_commands = USER_COMMANDS if user_commands is None else user_commands
        self.asyncio_server = None
        self.users = []
        self.bytes_sent = 0
        self.bytes_received = 0
        self.stop = False

    async def start(self):
        try:
            start_port = self.port
            iters = 0
            while 1:
                iters += 1
                try:
                    self.asyncio_server = await asyncio.start_server(self.handle_client, self.host, self.port)
                    break
                except OSError as ex:
                    if self.address_changing:
                        self.port += 1
                        if self.port > 25565:
                            self.port = 0
                    else:
                        self.logger.error(f'Can not find port to bind, {self.port} is already used')
                        raise ex

                if iters >= 10_000:
                    self.logger.error(f'Can not find port to bind, {start_port} is already used')
                    raise

            asyncio.create_task(self.garbage_collector())
            ciphers = f'{len(self.ciphers)} ciphers' if len(self.ciphers) > 1 else self.ciphers[0].__class__.__name__
            self.logger.info(f"SOCKS5 proxy running on {self.host}:{self.port} using {ciphers}")
            async with self.asyncio_server:
                await self.asyncio_server.serve_forever()
        except KeyboardInterrupt:
            self.logger.info("Server is closed")

    async def garbage_collector(self):
        while True:
            current_timestamp = time.time()
            for ip, timestamps in list(self.clients_tcp_timestamps.items()):
                while timestamps and current_timestamp - timestamps[0] >= SHORT_PERIOD_OF_TIME:
                    timestamps.popleft()
                if not timestamps:
                    self.clients_tcp_timestamps.pop(ip)

            await asyncio.sleep(1)


    async def handshake(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                        cipher: 'Cipher', default_cipher: 'Cipher', user: Optional['User'] = None) -> 'User':
        if user is None:
            client_ip, client_port = writer.get_extra_info("peername")
            user = await self.add_user(client_ip, client_port, writer)

        self.logger.debug('The server getting an auth methods')
        methods = await default_cipher.server_get_methods(self.socks_version, reader)

        if methods['supports_no_auth'] and self.accept_anonymous:
            self.logger.debug(f'{user} authorizing as Anonynous')
            data = await default_cipher.server_send_method_to_user(self.socks_version, 0x00)
            await self.send(user, data, log_bytes=False)
        elif methods['supports_user_pass']:
            self.logger.debug(f'{user} authorizing with username:password')
            data = await default_cipher.server_send_method_to_user(self.socks_version, 0x02)
            await self.send(user, data, log_bytes=False)

            self.logger.debug('The server is authorizing the client')
            auth_data = await default_cipher.server_auth_userpass(self.db_handler, reader, writer)
            if not auth_data:
                raise ConnectionError(f"Wrong authentication data {user}")

            user.username, user.password, user.key = auth_data
        else:
            data = await default_cipher.server_send_method_to_user(self.socks_version, 0xFF)
            await self.send(user, data, log_bytes=False)
            ms = ", ".join([m for m, enabled in methods.items() if enabled])
            raise ConnectionError(f'Can not use authentication method {user} - {ms}')

        user.handshaked = True
        cipher = cipher.__class__(user.key) if hasattr(cipher, 'key') and user.key else cipher.copy()
        if await cipher.server_finish_handshake(reader, writer):
            cipher.is_handshaked = True
            user.cipher = cipher
            self.logger.debug(f'{user} is handshaked')
            return user, cipher
        else:
            raise ConnectionError(f'{user} refused a handshake')

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

        connection_start_time = time.time()
        if client_ip not in self.clients_tcp_timestamps:
            self.clients_tcp_timestamps[client_ip] = deque(maxlen=CONN_ALIVE_MAX_NUMS)
        self.clients_tcp_timestamps[client_ip].append(connection_start_time)

        client_connections_score = (
            len(self.clients_tcp_timestamps.get(client_ip, [])) - CONNCETIONS_THRESHOLD
        ) / CONNCETIONS_THRESHOLD
        alive_time = self.clients_tcp_alive_time.get(client_ip, [])
        if alive_time:
            avg_time = sum(alive_time)/(len(alive_time) or 1)
            client_alive_time_score = 1/(avg_time)
        else:
            client_alive_time_score = 0

        client_score = client_connections_score - client_alive_time_score
        # print('score', client_score)

        user = await self.add_user(client_ip, client_port, writer)
        logging.debug(f'{user} is connecting...')
        default_cipher = self.ciphers[0].copy()

        try:
            if await default_cipher.server_hello(self, reader, writer):
                self.logger.debug(f"Sent server_hello of {default_cipher.wrapper.__class__.__name__}")
                try:
                    cipher = await default_cipher.server_get_cipher(self, self.ciphers, reader, writer)
                    self.logger.debug(f"Client choosed a cipher {cipher.__class__.__name__}")
                    user, cipher = await self.handshake(reader, writer, cipher, default_cipher, user=user)
                except ConnectionError as e:
                    self.logger.error(f'Suspicious client tried to connect: {user} => {e}')
                    return

                self.logger.info(f"{user} is connected with cipher {cipher.__class__.__name__}")
                addr, port, command = await cipher.server_handle_command(
                    self.socks_version, self.user_commands, reader
                )
                self.logger.info(f'Client {user} sent command {command.__qualname__} to {addr}:{port}')

                result_code, traffic_stats = await command(self, addr, port, user, cipher, reader, writer)
                self.logger.info(f'Сompleted the operation successfully, code: {result_code}')

            else:
                self.logger.warning(f'Suspicious client tried to connect: {user}')

        # except Exception as e:
        #     self.logger.error(f"Connection error: {repr(e)}")

        finally:
            alive_time = time.time() - connection_start_time
            if client_ip not in self.clients_tcp_alive_time:
                self.clients_tcp_alive_time[client_ip] = deque(maxlen=CONN_ALIVE_MAX_NUMS)
            self.clients_tcp_alive_time[client_ip].append(alive_time)

            await user.disconnect()

    async def pipe(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, name: str = 'default',
                   encrypt: Optional[callable] = None, decrypt: Optional[callable] = None, timeout: int = 300
                   ) -> Tuple[int, int]:
        try:
            bytes_received = 0
            bytes_sent = 0
            buffer = bytearray()
            while not reader.at_eof():
                data = await asyncio.wait_for(reader.read(4096), timeout=timeout)
                if not data:
                    break
                bytes_received += len(data)
                if self.log_bytes:
                    self.bytes_received += len(data)

                if decrypt:
                    data = decrypt(data)
                if encrypt:
                    data = encrypt(data)

                for frame in data:
                    writer.write(frame)
                    bytes_sent += len(frame)
                    if self.log_bytes:
                        self.bytes_sent += len(frame)

                await writer.drain()
        except asyncio.TimeoutError:
            pass
        except asyncio.CancelledError:
            pass
        except Exception as e:
            self.logger.error(f"Proxying PIPE '{name}' error: {repr(e)}")
        finally:
            await self.close_writer(writer)

        return bytes_sent, bytes_received

    @staticmethod
    async def close_writer(writer: asyncio.StreamWriter):
        try:
            writer.close()
        except:
            pass
        try:
            await asyncio.wait_for(writer.wait_closed(), timeout=5.0)
        except:
            pass
        try:
            writer.transport.abort()
        except:
            pass

    async def send(self, user: 'User', data: Union[bytes, List[bytes]], log_bytes: bool = True):
        if isinstance(data, list):
            for frame in data:
                user.writer.write(frame)
                if self.log_bytes and log_bytes:
                    self.bytes_sent += len(frame)
        else:
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
        try:
            user.writer.close()
            await self.close_writer(user.writer)
        except (ConnectionResetError, OSError):
            pass
        self.logger.info(f'{user} is disconnected')

    async def close(self):
        self.stop = True
        self.logger.info("Shutting down TCP server...")
        self.asyncio_server.close()
        await self.asyncio_server.wait_closed()
        self.logger.info("Server is closed")


    async def __aenter__(self):
        self.asyncio_server = await asyncio.start_server(self.handle_client, self.host, self.port)
        ciphers = f'{len(self.ciphers)} ciphers' if len(self.ciphers) > 1 else self.ciphers[0].__class__.__name__
        self.logger.info(f"SOCKS5 proxy running on {self.host}:{self.port} using {ciphers}")
        return self
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()

    def __str__(self):
        return f'{self.__class__.__name__}(host="{self.host}", port={self.port}, cipher={self.cipher})'


class User:
    def __init__(self, server: Socks5Server, ip: str, port: int, writer: asyncio.StreamWriter, id: Optional[int] = None,
                 key: str = '', handshaked: bool = False, username: str = 'Anonymous', password: Optional[str] = None,
                 cipher: Optional[Cipher] = None):

        self.server = server
        self.id = id
        self.ip = ip
        self.port = port
        self.writer = writer

        self.handshaked = handshaked
        self.username = username
        self.password = password
        self.key = key
        self.cipher = cipher

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
    def __init__(self, tcp_server: Socks5Server, user: User):
        self.tcp_server = tcp_server
        self.logger = self.tcp_server.logger
        self.cipher = self.tcp_server.udp_cipher.copy()
        self.user = user
        self.timeout = self.tcp_server.udp_server_timeout

        self.last_activity = time.time()
        self.fragment_buffer = {}
        self.host = None
        self.port = None
        self.client_addr: Optional[Tuple[str, int]] = None
        self.transport = None
        self.stop = False

        self.bytes_sent = 0
        self.bytes_received = 0

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
            data = b''.join(self.cipher.decrypt(data))
            if len(data) < 4:
                self.logger.warning("UDP packet too short for SOCKS5 header.")
                return

            rsv, frag, atyp = struct.unpack("!HBB", data[:4])

            offset = 4
            if atyp == 0x01:  # IPv4
                if len(data) < offset + 4 + 2:
                    self.logger.warning("Truncated IPv4 header in UDP packet.")
                    return
                offset += 4 + 2
            elif atyp == 0x03:  # Domain
                if len(data) < offset + 1:
                    self.logger.warning("Truncated domain length in UDP packet.")
                    return
                domain_len = data[offset]
                offset += domain_len + 2 + 1
            elif atyp == 0x04:  # IPv6
                if len(data) < offset + 16 + 2:
                    self.logger.warning("Truncated IPv6 header in UDP packet.")
                    return
                offset += 16 + 2
            else:
                self.logger.warning(f"Unknown ATYP={atyp} in UDP packet.")
                return

            dst_addr, dst_port = get_address(data[4:offset], atyp)
            payload = data[offset:]
            self.logger.debug(f"Client->Remote UDP: {len(payload)} bytes to {dst_addr}:{dst_port}")

            if atyp == 0x03:
                try:
                    dst_addr, dst_port = resolve_domain(dst_addr, dst_port)
                except Exception as e:
                    self.logger.warning(f"DNS resolve failed for {dst_addr}: {e}")
                    return

            if 0 < frag < 128:
                self.fragment_buffer[frag] = payload
            elif frag == 0:
                keys = list(sorted(self.fragment_buffer.keys()))
                if self.fragment_buffer:
                    if keys == list(range(keys[0], keys[-1] + 1)):
                        payload = b''.join(self.fragment_buffer[i] for i in keys) + payload
                    else:
                        self.logger.warning(f"Lost some packet from fragments, fragments was ignored")

                self.fragment_buffer = {}

                try:
                    self.transport.sendto(payload, (dst_addr, dst_port))
                    self.bytes_sent += len(payload)
                except Exception as e:
                    self.logger.error(f"UDP sendto failed {dst_addr}:{dst_port}: {e}")

        except Exception as e:
            self.logger.error(f"Failed to parse client UDP packet: {e}")

    def handle_remote(self, payload: bytes, addr: Tuple[str, int]):
        remote_ip, remote_port = addr
        self.logger.debug(f"Remote->Client UDP: {len(payload)} bytes from {remote_ip}:{remote_port}")

        try:
            atyp, addr_bytes = encode_ip(remote_ip)

            if atyp == 0x01:
                header = struct.pack("!HBB4sH", 0, 0, atyp, addr_bytes, remote_port)
            elif atyp == 0x04:
                header = struct.pack("!HBB16sH", 0, 0, atyp, addr_bytes, remote_port)
            else:  # domain
                header = struct.pack("!HBB", 0, 0, atyp) + addr_bytes + struct.pack("!H", remote_port)

            payload = b''.join(self.cipher.encrypt(header + payload))

            if self.client_addr:
                self.bytes_received += len(payload)
                self.transport.sendto(payload, self.client_addr)

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
                      client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter) -> Tuple[int, List[int]]:
        server.logger.debug(f"Establishing TCP connection for {user} to {addr}:{port}...")

        try:
            remote_reader, remote_writer = await asyncio.open_connection(addr, port)
            local_ip, local_port = remote_writer.get_extra_info("sockname")
            reply_frames = await cipher.server_make_reply(server.socks_version, REPLYES_CODES['succeeded'], local_ip, local_port)
            client_writer.write(b''.join(reply_frames))
            await client_writer.drain()
        except Exception as e:
            server.logger.warning(f"Failed to connect to {addr}:{port} => {e}")
            reply_frames = await cipher.server_make_reply(server.socks_version, REPLYES_CODES['host_unreachable'], '0.0.0.0', 0)
            client_writer.write(b''.join(reply_frames))
            await client_writer.drain()
            return 1, [0,0]

        server.logger.debug(f'{user} connected to {addr}:{port}')
        try:
            t1 = asyncio.create_task(server.pipe(client_reader, remote_writer, decrypt=cipher.decrypt, name='client -> server'))
            t2 = asyncio.create_task(server.pipe(remote_reader, client_writer, encrypt=cipher.encrypt, name='client <- server'))
            done, pending = await asyncio.wait([t1, t2], return_when=asyncio.FIRST_COMPLETED)
        except (ConnectionResetError, OSError):
            pass

        for t in pending:
            t.cancel()
            try:
                await t
            except asyncio.CancelledError:
                pass

        c2s_bytes = [0, 0]
        s2c_bytes = [0, 0]

        if t1.done():
            try:
                c2s_bytes = t1.result()
            except asyncio.CancelledError:
                pass
        if t2.done():
            try:
                s2c_bytes = t2.result()
            except asyncio.CancelledError:
                pass

        server.logger.debug(f"TCP connection to {addr}:{port} is closed")
        return 0, c2s_bytes

    @staticmethod
    async def BIND(server: Socks5Server, addr: str, port: int, user: User, cipher: Cipher,
                   client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter) -> Tuple[int, List[int]]:
        server.logger.error(f"bind_socket {addr}:{port}")
        return 0, [0,0]

    @staticmethod
    async def UDP_ASSOCIATE(server: Socks5Server, addr: str, port: int, user: User, cipher: Cipher,
                            client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter
                            ) -> Tuple[int, List[int]]:

        server.logger.debug("Starting UDP server...")
        loop = asyncio.get_running_loop()

        try:
            transport, protocol = await loop.create_datagram_endpoint(
                lambda: UDPServerProxy(server, user),
                local_addr=('0.0.0.0', 0)
            )
        except Exception as e:
            server.logger.error(f"Failed to start UDP relay: {e}")
            reply = b''.join(await cipher.server_make_reply(server.socks_version, REPLYES_CODES['failure'], '0.0.0.0', 0))
            client_writer.write(reply)
            await client_writer.drain()
            return 1, [0,0]

        udp_host, udp_port = transport.get_extra_info('sockname')
        server.logger.info(f"Started UDP server for {addr}:{port} at {udp_host}:{udp_port}")

        try:
            reply = b''.join(await cipher.server_make_reply(server.socks_version, REPLYES_CODES['succeeded'], udp_host, udp_port))
            client_writer.write(reply)
            await client_writer.drain()
        except Exception as e:
            self.logger.warning(f"Failed to make UDP connection at TCP {addr}:{port}; UDP {udp_host}:{udp_port} => {e}")
            reply = b''.join(await default_cipher.server_make_reply(self.socks_version, 0xFF, '0.0.0.0', 0))
            client_writer.write(reply)
            await client_writer.drain()
            return 1, [0,0]

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

                    await asyncio.sleep(1)
                except Exception as e:
                    server.logger.warning(f"UDP_ASSOCIATE TCP connection error: {e}")
                    break
        finally:
            transport.close()

        return 0, [protocol.bytes_sent, protocol.bytes_received]


USER_COMMANDS = {
    0x01: ConnectionMethods.CONNECT,
    0x02: ConnectionMethods.BIND,
    0x03: ConnectionMethods.UDP_ASSOCIATE,
}