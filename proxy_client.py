from typing import *
import traceback
import asyncio
import socket
import logging
import ipaddress
import struct
import time

from .logger_setup import *
from .base_cipher import Cipher, REPLYES_CODES, get_address
from .proxy_server import Socks5Server, ConnectionMethods, UDPServerProxy


class Socks5Client:
    def __init__(self, ciphers: List[Cipher] = [Cipher()], cipher_key: bytes = '', cipher_index: int = 0,
                 udp_cipher: Optional[Cipher] = None, log_bytes: bool = False, default_socks5: bool = False):
        self.socks_version = 5
        self.log_bytes = log_bytes # only after handshake
        self.default_socks5 = default_socks5
        self.ciphers = ciphers
        self.cipher_index = cipher_index
        self.cipher_key = cipher_key
        self.udp_cipher = Cipher() if udp_cipher is None else udp_cipher
        self.udp_socket = None
        self.bytes_sent = 0
        self.bytes_received = 0
        self.logger = logging.getLogger(__name__)

        for cipher in self.ciphers:
            cipher.is_client = True
        self.udp_cipher.is_client = True

        self.user_commands = {
            'ping': 0x00,
            'connect': 0x01,
            'bind': 0x02,
            'associate': 0x03,
        }
        self.sessions = []

    async def handshake(self, proxy_host: str = '127.0.0.1', proxy_port: int = 1080, username: Optional[str] = None,
                        password: Optional[str] = None, proxying_mode: int = 0, logging: bool = True,
                        session_class = None) -> 'TCP_ProxySession':
        reader, writer = await asyncio.open_connection(proxy_host, proxy_port)
        try:
            cipher = self.ciphers[self.cipher_index]
            if hasattr(cipher, 'key') and self.cipher_key:
                cipher = cipher.__class__(self.cipher_key)
            default_cipher = self.ciphers[0].copy()
        except IndexError:
            raise IndexError(f'Invalid cipher index choosed: {self.cipher_index} of list {self.ciphers}')

        session_class = TCP_ProxySession if session_class is None else session_class
        session = session_class(self, reader, writer, cipher, proxy_host, proxy_port,
                                username=username, password=password, log_bytes=self.log_bytes)
        self.sessions.append(session)
        if logging:
            self.logger.info(
                f"Connected to SOCKS5 proxy at {proxy_host}:{proxy_port} using {self.ciphers[self.cipher_index].__class__.__name__}"
            )
        await default_cipher.client_hello(self, reader, writer)
        if logging: self.logger.debug("Sent client_hello")
        if not self.default_socks5:
            if await default_cipher.client_start_handshake(self, self.cipher_index, proxying_mode, reader, writer):
                if logging: self.logger.debug("Sent a cipher to the server")
            else:
                raise ConnectionError(f"Server has denied choosed cipher {self.cipher_index}")

        methods = [0x00]
        if username and password:
            methods.insert(0, 0x02)

        if logging: self.logger.debug("Sent auth methods")
        methods_msg = await default_cipher.client_send_methods(self.socks_version, methods)

        await self.trace_event(session.asend(methods_msg, encrypt=False, log_bytes=False), event_name=f'CLIENT_HELLO')
        if logging: self.logger.debug("Receiving server auth method")
        method_chosen = await self.trace_event(
            default_cipher.client_get_method(self.socks_version, reader),
            event_name=f'GETTING_AUTH_METHODS'
        )

        try:
            if method_chosen == 0xFF:
                raise ConnectionError("No acceptable authentication methods.")

            if method_chosen == 0x02:
                if not username or not password:
                    raise ConnectionError("Proxy requires username/password authentication, but none provided")

                if logging: self.logger.debug("Client is authorizing")
                auth_ok = await self.trace_event(
                    default_cipher.client_auth_userpass(username, password, reader, writer),
                    event_name='AUTH'
                )
                if not auth_ok:
                    raise ConnectionError("Authentication failed")
                if logging: self.logger.info("Authenticated successfully")

            elif method_chosen == 0x00:
                if logging: self.logger.info("No authentication required by proxy")

            else:
                raise ConnectionError(f"Unsupported authentication method selected by proxy: {method_chosen}")

            if await session.cipher.client_finish_handshake(reader, writer):
                if logging: self.logger.debug("Handshaked")
                session.cipher.is_handshaked = True
                return session
            else:
                raise ConnectionError(f'{user} refused a handshake')
        except Exception as ex:
            if logging: self.logger.error(ex)
            raise ex


    async def ping(self, proxy_host: str = '127.0.0.1', proxy_port: int = 1080, username: Optional[str] = None,
                   password: Optional[str] = None) -> bool:
        try:
            self.logger.debug(f"Ping to proxy")
            session = await self.handshake(proxy_host=proxy_host, proxy_port=proxy_port,
                                           username=username, password=password, logging=False)

            cmd_bytes = await session.cipher.client_command(self.socks_version, self.user_commands['ping'], '0.0.0.0', 0)
            await self.trace_event(session.asend(cmd_bytes, encrypt=False, log_bytes=False), event_name=f'CLIENT_CMD_SEND')

            address, port = await self.trace_event(
                session.cipher.client_connect_confirm(session.reader),
                event_name=f'SERVER_CMD_CONFIRM'
            )

            self.logger.debug(f"Pong from proxy")
            return address == '0.0.0.0' and port == 0
        except Exception as ex:
            self.logger.debug(f'Ping received an error: {ex}')
            return False

    async def connect(self, target_host: str, target_port: int,
                            proxy_host: str = '127.0.0.1', proxy_port: int = 1080,
                            username: Optional[str] = None, password: Optional[str] = None) -> 'TCP_ProxySession':

        session = await self.handshake(proxy_host=proxy_host, proxy_port=proxy_port, username=username, password=password)

        cmd_bytes = await session.cipher.client_command(
            self.socks_version, self.user_commands['connect'], target_host, target_port
        )
        await self.trace_event(session.asend(cmd_bytes, encrypt=False, log_bytes=False), event_name=f'CLIENT_CMD_SEND')

        address, port = await self.trace_event(
            session.cipher.client_connect_confirm(session.reader),
            event_name=f'SERVER_CMD_CONFIRM'
        )

        self.logger.debug(f"Connected to {target_host}:{target_port} through proxy")
        return session

    async def udp_associate(self, target_host: str, target_port: int,
                                  proxy_host: str = '127.0.0.1', proxy_port: int = 1080,
                                  username: Optional[str] = None, password: Optional[str] = None
                                  ) -> Tuple['UDP_ProxySession', 'TCP_ProxySession']:

        session = await self.handshake(proxy_host=proxy_host, proxy_port=proxy_port,
                                              username=username, password=password)

        cmd_bytes = await session.cipher.client_command(
            self.socks_version, self.user_commands['associate'], target_host, target_port
        )
        await self.trace_event(session.asend(cmd_bytes, encrypt=False, log_bytes=False), event_name=f'CLIENT_CMD_SEND')

        udp_host, udp_port = await self.trace_event(
            session.cipher.client_connect_confirm(session.reader),
            event_name=f'SERVER_CMD_CONFIRM'
        )
        udp_session = await UDP_ProxySession.create(udp_host, udp_port, self.udp_cipher.copy(), target_host, target_port)

        self.logger.debug(f"Got an associated UDP server {udp_session.host}:{udp_session.port} through proxy")
        return udp_session, session


    async def trace_event(self, coro: Awaitable, event_name: str, ex_class: Exception = ConnectionError):
        try:
            return await coro
        except Exception as ex:
            if self.logger.isEnabledFor(logging.DEBUG):
                traceback.print_exc()
            raise ex_class(f'Error when {event_name}: "{ex}"')


    async def close(self, session: Optional['Session'] = None):
        if session:
            await session.close()
            self.logger.info("1 connection closed")
        else:
            for session in self.sessions:
                await session.close()
            self.logger.info(f"{len(self.sessions)} connections closed")

    async def __aenter__(self):
        return self
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()

    def __str__(self):
        return f'{self.__class__.__name__}({len(self.sessions)} connections, cipher={self.ciphers[0].__class__.__name__})'


class TCP_ProxySession:
    def __init__(self, client: Socks5Client, reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                 cipher: 'Cipher', host: str, port: int, username: str = '', password: str = '', log_bytes: bool = False):
        self.client = client
        self.logger = self.client.logger
        self.reader = reader
        self.writer = writer
        self.cipher = cipher.copy()
        self.host = host
        self.port = port

        self.username = username
        self.password = password
        self.log_bytes = log_bytes

        self.closed = False
        self.addr = f'{self.host}:{self.port}'
        self._pt_buffer = bytearray()


    async def asend(self, data: Union[bytes, List[bytes]], encrypt: bool = True, log_bytes: bool = True, wait: bool = True):
        if encrypt:
            data = self.cipher.encrypt(data)

        length = 0
        if isinstance(data, list):
            for frame in data:
                if self.log_bytes and log_bytes:
                    self.bytes_sent += len(frame)
                self.writer.write(frame)
                length += len(frame)
        else:
            self.writer.write(data)
            length = len(data)
        if wait:
            await self.writer.drain()
        self.logger.debug(f"Sent {length} bytes to TCP proxy {self.addr}")

    def send(self, data: Union[bytes, List[bytes]], encrypt: bool = True, log_bytes: bool = True, wait: bool = True):
        return asyncio.run(self.asend(data, encrypt=encrypt, log_bytes=log_bytes, wait=wait))


    async def aread(self, num_bytes: int = -1, decrypt: bool = True, log_bytes: bool = True, **kwargs) -> bytes:
        # "num_bytes == -1" - means that aread will return every byte before the connection is closed

        if num_bytes < -1 or num_bytes == 0:
            return b''

        buffer_length = len(self._pt_buffer)
        if num_bytes == -1:
            data = await self.reader.read(-1)
            if self.log_bytes and log_bytes:
                self.bytes_received += len(data)
            data = self._pt_buffer + (b''.join(self.cipher.decrypt(data, **kwargs)) if decrypt and data else data)
            self._pt_buffer = bytearray()
        elif num_bytes == buffer_length:
            data = self._pt_buffer
            self._pt_buffer = bytearray()
        elif num_bytes > buffer_length:
            data = await self.reader.read(num_bytes - buffer_length)
            if self.log_bytes and log_bytes:
                self.bytes_received += len(data)
            data = self._pt_buffer + (b''.join(self.cipher.decrypt(data, **kwargs)) if decrypt and data else data)
            self._pt_buffer = bytearray()
        else:
            data = self._pt_buffer[:num_bytes]
            del self._pt_buffer[:num_bytes]

        self.logger.debug(f"Readed {len(data)} bytes from TCP proxy {self.addr}")
        return data

    async def areadexactly(self, num_bytes: int, decrypt: bool = True, log_bytes: bool = True, **kwargs) -> bytes:
        buffer_length = len(self._pt_buffer)
        if num_bytes == buffer_length:
            data = self._pt_buffer
            self._pt_buffer = bytearray()
        elif num_bytes > buffer_length:
            data = await self.reader.readexactly(num_bytes - buffer_length)
            if self.log_bytes and log_bytes:
                self.bytes_received += len(data)
            data = self._pt_buffer + (b''.join(self.cipher.decrypt(data, **kwargs)) if decrypt else data)
            self._pt_buffer = bytearray()
        else:
            data = self._pt_buffer[:num_bytes]
            del self._pt_buffer[:num_bytes]

        self.logger.debug(f"Readed {len(data)} bytes from TCP proxy {self.addr}")
        return data

    async def areaduntil(self, sep: Union[str, bytes] = '\n', decrypt: bool = True, log_bytes: bool = True,
                         bytes_block: int = 1024, limit: int = 65535, **kwargs) -> bytes:
        sep = sep.encode() if isinstance(sep, str) else sep

        pos = self._pt_buffer.find(sep)
        if pos != -1:
            data = self._pt_buffer[:pos + len(sep)]
            del self._pt_buffer[:pos + len(sep)]
            self.logger.debug(f"Readed {len(data)} bytes from TCP proxy {self.addr}")
            return data

        if not decrypt:
            try:
                data = await (self.reader.readline() if sep == b'\n' else self.reader.readuntil(sep))
            except asyncio.IncompleteReadError as e:
                data = e.partial
            if self.log_bytes and log_bytes:
                self.bytes_received += len(data)
                self.logger.debug(
                    f"Readed {len(self._pt_buffer + data)} bytes from TCP proxy {self.addr}"
                )
            return self._pt_buffer + data

        while True:
            chunk = await self.reader.read(bytes_block)
            if not chunk:
                break

            if self.log_bytes and log_bytes:
                self.bytes_received += len(chunk)

            self._pt_buffer += b''.join(self.cipher.decrypt(chunk, **kwargs))

            pos = self._pt_buffer.find(sep)
            if pos != -1:
                data = self._pt_buffer[:pos + len(sep)]
                del self._pt_buffer[:pos + len(sep)]
                self.logger.debug(f"Readed {len(data)} bytes from TCP proxy {self.addr}")
                return data

        data = self._pt_buffer
        self._pt_buffer = bytearray()
        self.logger.debug(f"Readed {len(data)} bytes from TCP proxy {self.addr}")
        return data

    async def areadline(self, log_bytes: bool = True, decrypt: bool = True, limit: int = 65535, **kwargs) -> bytes:
        if 'sep' in kwargs.keys():
            kwargs.pop('sep')
        return await self.areaduntil(self.reader, sep='\n', decrypt=decrypt, log_bytes=log_bytes, limit=limit, **kwargs)


    def get_sockname(self) -> Tuple[str, int]:
        return self.writer.get_extra_info("sockname")

    async def close(self):
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
        self.closed = True
        self.logger.debug(f"{self.client} session closed to {self.addr}")

    async def __aenter__(self):
        return self
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()

    def __str__(self):
        return f'{self.__class__.__name__}(host={self.host}, port={self.port})'
    def __repr__(self):
        return f'<{self.__class__.__name__} host={self.host} port={self.port}>'

class UDP_ProxySession(asyncio.DatagramProtocol):
    def __init__(self, cipher: 'Cipher', dst_ip: str, dst_port: int):
        self.transport = None
        self.recv_queue = asyncio.Queue()
        self.logger = logging.getLogger(__name__)
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.host = 'N/A'
        self.port = 0
        self.cipher = cipher.copy()

        self.client_ip = 'N/A'
        self.client_port = 0
        self.addr = f'{self.host}:{self.port}'


    def send(self, data: bytes):
        header_socks5 = self.format_socks5_udp_header(self.dst_ip, self.dst_port)
        self.raw_send(b''.join(self.cipher.encrypt(header_socks5 + data)))
        self.logger.debug(f"Sent {len(data)} bytes to UDP proxy {self.addr}")

    async def recv(self, timeout: int = 5) -> Tuple[bytes, Tuple[str, int]]:
        data = await asyncio.wait_for(self.raw_recv(), timeout=timeout)
        self.logger.debug(f"Readed {len(data)} bytes from UDP proxy {self.addr}")
        return b''.join(self.cipher.decrypt(data[0])), data[1]


    def format_socks5_udp_header(self, host: str, port: int) -> bytes:
        rsv = 0
        frag = 0

        try: # IPv(4/6)
            ip = ipaddress.ip_address(host)
            if ip.version == 4:
                atyp = 1  # IPv4
                addr_bytes = ip.packed
            else:
                atyp = 4  # IPv6
                addr_bytes = ip.packed
        except ValueError:
            atyp = 3  # Domain
            host_bytes = host.encode("idna")
            if len(host_bytes) > 255:
                raise ValueError("Domain name too long for SOCKS5 (max 255 bytes)")
            addr_bytes = bytes([len(host_bytes)]) + host_bytes

        return struct.pack("!HB", rsv, frag) + bytes([atyp]) + addr_bytes + struct.pack("!H", port)


    def connection_made(self, transport):
        self.transport = transport
        try:
            self.client_ip, self.client_port = self.transport.get_extra_info("peername")
        except TypeError:
            pass

        self.logger.debug(f"Server {self} has client connected {self.client_ip}:{self.client_port}")

    def datagram_received(self, data, addr):
        self.client_ip, self.client_port = addr
        self.recv_queue.put_nowait((data, addr))

    def error_received(self, exc):
        self.logger.error(f"{self} error: {exc}")

    def connection_lost(self, exc):
        self.logger.error(f"{self} connection with {self.client_ip}:{self.client_port} closed")

    def raw_send(self, data: bytes):
        if self.transport is not None:
            self.transport.sendto(data)

    async def raw_recv(self):
        data, addr = await self.recv_queue.get()
        if data is None:
            raise ConnectionError(f"{self} connection closed")
        return data, addr

    def close(self):
        if self.transport:
            self.transport.close()
            self.transport = None
        self.recv_queue.put_nowait((None, None))

    @staticmethod
    async def create(host: str, port: int, cipher: 'Cipher', target_host: str, target_port: int) -> 'UDP_ProxySession':
        loop = asyncio.get_running_loop()
        transport, protocol = await loop.create_datagram_endpoint(
            lambda: UDP_ProxySession(cipher, target_host, target_port),
            remote_addr=('127.0.0.1', port)
        )
        protocol.transport = transport
        protocol.host, protocol.port = protocol.transport.get_extra_info('sockname')
        return protocol

    async def __aenter__(self):
        return self
    async def __aexit__(self, exc_type, exc, tb):
        self.close()


    def __str__(self):
        return f'{self.__class__.__name__}(host="{self.host}", port={self.port})'
    def __repr__(self):
        return f'<{self.__class__.__name__} host={self.host} port={self.port}>'


class Socks5_UDP_Retranslator(UDP_ProxySession):
    def __init__(self, remote_host: str, remote_port: int, *args, timeout: int = 5*60, **kwargs):
        super().__init__(*args, remote_host, remote_port, **kwargs)
        self.remote_host = remote_host
        self.remote_port = remote_port
        self.timeout = timeout

        self.client_addr: Optional[Tuple[str, int]] = None
        self.client_addr_format = None
        self.last_activity = time.time()
        self.stop = False

    def connection_made(self, transport):
        super().connection_made(transport)
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
        self.logger.debug(f"{self} datagram from {addr}")

        if self.client_addr is None:
            self.client_addr = addr
            self.client_addr_format = f'{self.client_addr[0]}:{self.client_addr[1]}'

        try:
            if addr == self.client_addr: # from client
                for packet in self.cipher.encrypt(data):
                    self.transport.sendto(packet, (self.remote_host, self.remote_port))
                self.logger.debug(
                    f"{self.client_addr_format}->{self.remote_host}:{self.remote_port} translated {len(data)} bytes"
                )
            else: # from server
                for packet in self.cipher.decrypt(data):
                    self.transport.sendto(packet, self.client_addr)
                self.logger.debug(
                    f"{self.client_addr_format}<-{self.remote_host}:{self.remote_port} translated {len(data)} bytes"
                )

        except Exception as e:
            self.logger.error(f"UDP relay error: {e}")

    @staticmethod
    async def create(host: str, port: int, cipher: 'Cipher') -> 'Socks5_UDP_Retranslator':
        loop = asyncio.get_running_loop()
        transport, protocol = await loop.create_datagram_endpoint(
            lambda: Socks5_UDP_Retranslator(host, port, cipher),
            local_addr=('0.0.0.0', port)
        )
        protocol.transport = transport
        protocol.host, protocol.port = protocol.transport.get_extra_info('sockname')
        return protocol

    def connection_lost(self, exc):
        super().connection_lost(exc)
        self.stop = True

class Socks5_TCP_Retranslator(Socks5Client):
    def __init__(self, remote_host: str, remote_port: int, *args, username: str = '', password: str = '', **kwargs):
        super().__init__(*args, **kwargs)
        self.remote_host = remote_host
        self.remote_port = remote_port
        self.username = username
        self.password = password

        self.pipe = Socks5Server.pipe
        self.close_writer = Socks5Server.close_writer
        self.server_commands = {
            0x00: self.PING,
            0x01: self.CONNECT,
            0x02: self.BIND,
            0x03: self.UDP_ASSOCIATE,
        }
        self.default_commands = {
            self.PING: ConnectionMethods.PING,
            self.CONNECT: ConnectionMethods.CONNECT,
            self.BIND: ConnectionMethods.BIND,
            self.UDP_ASSOCIATE: ConnectionMethods.UDP_ASSOCIATE,
        }

        self._local_host = 'localhost'
        self._local_host = 0

        self.local_server = None

    async def async_listen_and_forward(self, local_host: str = '127.0.0.1', local_port: int = 1080, ping: bool = True):
        try:
            if ping:
                self.server_is_available = await self.ping(proxy_host=self.remote_host, proxy_port=self.remote_port,
                                                       username=self.username, password=self.password)
            else:
                self.server_is_available = True

            if self.server_is_available:
                self.local_server = Socks5Server(host=local_host, port=local_port, accept_anonymous=True)
                self.local_server.handle_client = self.handle_local_client
                self.logger.info(f"Retranslator started at {local_host}:{local_port} for {self.remote_host}:{self.remote_port}")
                self.local_server.logger = self.logger

                self._local_host = self.local_server.host
                self._local_host = self.local_server.port

                await self.local_server.start()
            else:
                self.logger.error(f"Server is not available {self.remote_host}:{self.remote_port}")

        except KeyboardInterrupt:
            self.logger.info('Client closed by user')
        except RuntimeError:
            self.logger.info('Client closed by user')

    def listen_and_forward(self, *args, **kwargs):
        try:
            asyncio.run(self.async_listen_and_forward(*args, **kwargs))
        except KeyboardInterrupt:
            self.logger.info('Client closed by user')


    async def handle_local_client(self, client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter):
        try:
            addr, port, command, default_cipher, user = await self.listen_local_cmd(client_reader, client_writer)
        except Exception as e:
            self.logger.error(
                f"Can not do handshake to local proxy {self.local_server.host}:{self.local_server.port} — {e}"
            )
            client_writer.close()
            await client_writer.wait_closed()
            return

        try:
            remote_session = await self.handshake(
                proxy_host=self.remote_host, proxy_port=self.remote_port, username=self.username, password=self.password
            )
            self.logger.debug(f'Client {user} handshaked with remote server')
        except ConnectionRefusedError:
            self.logger.error(f"Can not connect to remote proxy {self.remote_host}:{self.remote_port}")
            client_writer.close()
            await client_writer.wait_closed()
            return
        except Exception as e:
            self.logger.error(f"Can not do handshake to remote proxy {self.remote_host}:{self.remote_port} - {e}")
            try:
                client_writer.close()
                await client_writer.wait_closed()
            except:
                pass
            return

        try:
            status_code = await command(user, addr, port, default_cipher, remote_session, client_writer, client_reader)
            self.logger.debug(f"Connection to {addr}:{port} is closed, code: {status_code}")
            await self.close_writer(client_writer)
        except Exception as e:
            if self.logger.isEnabledFor(logging.DEBUG):
                traceback.print_exc()
            self.logger.error(f"Running client cmd error {self.remote_host}:{self.remote_port} - {e}")
            try:
                client_writer.close()
                await client_writer.wait_closed()
            except:
                pass
        try:
            await remote_session.close()
        except:
            pass


    async def PING(self, user: 'User', addr: str, port: int, default_cipher: Cipher, remote_session: TCP_ProxySession,
                      client_writer: asyncio.StreamWriter, client_reader: asyncio.StreamReader) -> int:
        if not (await self.is_valid_connect_addr(user, addr, port)):
            return 1

        cmd_bytes = await remote_session.cipher.client_command(
            self.socks_version, self.user_commands['ping'], addr, port
        )
        await self.trace_event(remote_session.asend(cmd_bytes, encrypt=False, log_bytes=False), event_name='CLIENT_CMD_SEND')
        try:
            address, port = await self.trace_event(
                remote_session.cipher.client_connect_confirm(remote_session.reader), event_name='SERVER_CMD_CONFIRM'
            )
        except ConnectionError as e:
            self.logger.error(e)
            return 1

        return 0

    async def CONNECT(self, user: 'User', addr: str, port: int, default_cipher: Cipher, remote_session: TCP_ProxySession,
                      client_writer: asyncio.StreamWriter, client_reader: asyncio.StreamReader) -> int:
        if not (await self.is_valid_connect_addr(user, addr, port)):
            return 1

        self.logger.debug(f"Sending a selected command to server...")
        cmd_bytes = await remote_session.cipher.client_command(
            self.socks_version, self.user_commands['connect'], addr, port
        )
        await self.trace_event(remote_session.asend(cmd_bytes, encrypt=False, log_bytes=False), event_name='CLIENT_CMD_SEND')
        try:
            address, port = await self.trace_event(
                remote_session.cipher.client_connect_confirm(remote_session.reader), event_name='SERVER_CMD_CONFIRM'
            )
        except ConnectionError as e:
            self.logger.error(e)
            return 1


        try:
            local_ip, local_port = remote_session.get_sockname()
            reply_frames = await default_cipher.server_make_reply(
                self.socks_version, REPLYES_CODES['succeeded'], local_ip, local_port
            )
            client_writer.write(b''.join(reply_frames))
            await client_writer.drain()
        except Exception as e:
            self.logger.warning(f"Failed to connect to {addr}:{port} => {e}")
            reply_frames = await default_cipher.server_make_reply(
                self.socks_version, REPLYES_CODES['failure'], '0.0.0.0', 0
            )
            try:
                client_writer.write(b''.join(reply_frames))
                await client_writer.drain()
            except:
                pass
            return 1

        self.logger.debug(f"Establishing TCP connection to {addr}:{port}...")
        await self.make_tcp_pipes(client_reader, remote_session.writer, remote_session.reader, client_writer,
                                  remote_session.cipher.encrypt, remote_session.cipher.decrypt)
        
        return 0

    async def UDP_ASSOCIATE(self, user: 'User', addr: str, port: int, default_cipher: Cipher,
                            remote_session: TCP_ProxySession,
                            client_writer: asyncio.StreamWriter, client_reader: asyncio.StreamReader) -> int:
        self.logger.debug("Starting UDP server...")
        cmd_bytes = await remote_session.cipher.client_command(
            self.socks_version, self.user_commands['associate'], addr, port
        )
        await self.trace_event(remote_session.asend(cmd_bytes, encrypt=False, log_bytes=False),
                               event_name='CLIENT_CMD_SEND')
        address, port = await self.trace_event(remote_session.cipher.client_connect_confirm(remote_session.reader),
                                               event_name='SERVER_CMD_CONFIRM')

        self.logger.debug(f"Establishing UDP connection to {address}:{port}...")
        loop = asyncio.get_running_loop()

        try:
            udp_session = await Socks5_UDP_Retranslator.create(
                self.remote_host, port, self.udp_cipher
            )
        except Exception as e:
            self.logger.error(f"Failed to start UDP relay: {e}")
            reply = await default_cipher.server_make_reply(self.socks_version, REPLYES_CODES['failure'], '0.0.0.0', 0)
            for r in reply:
                client_writer.write(r)
            await client_writer.drain()
            return 1

        self.logger.info(f"Started UDP server for {addr}:{port} at {udp_session.host}:{udp_session.port}")

        try:
            reply = await default_cipher.server_make_reply(self.socks_version, REPLYES_CODES['succeeded'],
                                                           udp_session.host, udp_session.port)
            for r in reply:
                client_writer.write(r)
            await client_writer.drain()
        except Exception as e:
            self.logger.warning(f"Failed to make UDP connection at TCP {addr}:{port}; UDP {udp_host}:{udp_port} => {e}")
            try:
                client_writer.write(
                    await default_cipher.server_make_reply(self.socks_version, REPLYES_CODES['failure'], '0.0.0.0', 0))
                await client_writer.drain()
            except:
                pass
            return 1

        try:
            while True:
                try:
                    if self.local_server.stop:
                        self.logger.debug("Server stopping: closing UDP assoc.")
                        break
                    if not user.connected:
                        self.logger.debug("User disconnected: closing UDP assoc.")
                        break

                    if client_reader.at_eof():
                        self.logger.debug("TCP reader EOF: closing UDP assoc.")
                        break
                    if client_writer.is_closing():
                        self.logger.debug("TCP writer closing: closing UDP assoc.")
                        break

                    await asyncio.sleep(2)
                except Exception as e:
                    self.logger.warning(f"UDP_ASSOCIATE TCP connection error: {e}")
                    break
        finally:
            udp_session.close()

    async def BIND(self, user: 'User', addr: str, port: int, default_cipher: Cipher, remote_session: TCP_ProxySession,
                   client_writer: asyncio.StreamWriter, client_reader: asyncio.StreamReader) -> int:
        cmd_bytes = await remote_cipher.client_command(
            self.socks_version, self.user_commands['bind'], addr, port
        )
        await remote_session.asend(cmd_bytes, encrypt=False, log_bytes=False)
        address, port = await remote_session.cipher.client_connect_confirm(remote_session.reader)
        return 1


    async def is_valid_connect_addr(self, user: 'User', addr: str, port: int) -> bool:
        if (addr == '0.0.0.0' and port == 0) or (addr.startswith('192.168') or addr.startswith('10.') or
                                                 addr.startswith('127.')) or addr == self.remote_host:
            self.logger.debug(
                f'INVALID IP ADDRESS TO CONNECT: Ignored {user}`s request to {addr}. You may try to reboot the '
                f'computer to delete this message.'
            )
            try:
                reply = await default_cipher.server_make_reply(self.socks_version, REPLYES_CODES['failure'],
                                                               '0.0.0.0', 0)
                for r in reply:
                    client_writer.write(r)
                await client_writer.drain()
            except Exception as e:
                try:
                    client_writer.write(
                        await default_cipher.server_make_reply(self.socks_version, REPLYES_CODES['failure'],
                                                               '0.0.0.0', 0)
                    )
                    await client_writer.drain()
                except:
                    pass
            return False
        return True

    async def listen_local_cmd(self, client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter
                               ) -> Tuple[str, int, Callable, Cipher, 'User', bool]:
        default_cipher = self.local_server.ciphers[0].copy()
        self.logger.debug('Local client connecting...')
        user, default_cipher = await self.local_server.handshake(client_reader, client_writer, default_cipher, default_cipher)

        self.logger.info(f'Local client connected {user}')

        addr, port, command = await default_cipher.server_handle_command(
            self.socks_version, self.server_commands, client_reader
        )
        self.logger.info(f'Local client {user} sent command {command.__qualname__} to {addr}:{port}')
        return addr, port, command, default_cipher, user

    async def make_tcp_pipes(self, client_reader: asyncio.StreamReader, remote_writer: asyncio.StreamWriter,
                             remote_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter,
                             encrypt: Callable[[bytes], List[bytes]], decrypt: Callable[[bytes], List[bytes]]
                             ) -> Tuple:
        try:
            t1 = asyncio.create_task(
                self.pipe(self, client_reader, remote_writer, encrypt=encrypt, name='client -> server')
            )
            t2 = asyncio.create_task(
                self.pipe(self, remote_reader, client_writer, decrypt=decrypt, name='client <- server')
            )
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

        return c2s_bytes, s2c_bytes