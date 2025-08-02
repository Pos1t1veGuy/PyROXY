from typing import *
import asyncio
import socket
import logging
import ipaddress
import struct

from .logger_setup import *
from .base_cipher import Cipher, REPLYES_CODES
from .proxy_server import Socks5Server, ConnectionMethods, UDPServerProxy


class Socks5Client:
    def __init__(self, ciphers: List[Cipher] = [Cipher()], cipher_index: int = 0,
                 udp_cipher: Optional[Cipher] = None,  log_bytes: bool = False):
        self.socks_version = 5
        self.log_bytes = log_bytes # only after handshake
        self.ciphers = ciphers
        self.cipher_index = cipher_index
        self.udp_cipher = Cipher() if udp_cipher is None else udp_cipher
        self.udp_socket = None
        self.bytes_sent = 0
        self.bytes_received = 0
        self.logger = logging.getLogger(__name__)

        for cipher in self.ciphers:
            cipher.is_client = True
        self.udp_cipher.is_client = True

        self.user_commands = {
            'connect': 0x01,
            'bind': 0x02,
            'associate': 0x03,
        }
        self.sessions = []

    async def handshake(self, proxy_host: str = '127.0.0.1', proxy_port: int = 1080, username: Optional[str] = None,
                        password: Optional[str] = None) -> 'TCP_ProxySession':
        reader, writer = await asyncio.open_connection(proxy_host, proxy_port)
        try:
            cipher = self.ciphers[self.cipher_index].copy()
        except IndexError:
            raise IndexError(f'Invalid cipher index choosed: {self.cipher_index} of list {self.ciphers}')
        session = TCP_ProxySession(self, reader, writer, cipher, proxy_host, proxy_port,
                                   username=username, password=password, log_bytes=self.log_bytes)
        self.sessions.append(session)
        self.logger.info(
            f"Connected to SOCKS5 proxy at {proxy_host}:{proxy_port} using {self.ciphers[0].__class__.__name__}"
        )
        default_cipher = self.ciphers[0].copy()
        await default_cipher.client_hello(self, reader, writer)
        self.logger.debug("Sent client_hello")
        if await default_cipher.client_send_cipher(self, self.cipher_index, reader, writer):
            self.logger.debug("Sent a cipher to the server")
        else:
            raise ConnectionError(f"Server has denied choosed cipher {self.cipher_index}")

        methods = [0x00]
        if username and password:
            methods.insert(0, 0x02)

        self.logger.debug("Sent auth methods")
        methods_msg = await session.cipher.client_send_methods(self.socks_version, methods)
        await session.asend(methods_msg, encrypt=False, log_bytes=False)
        self.logger.debug("Receiving server auth method")
        method_chosen = await session.cipher.client_get_method(self.socks_version, reader)

        try:
            if method_chosen == 0xFF:
                raise ConnectionError("No acceptable authentication methods.")

            if method_chosen == 0x02:
                if not username or not password:
                    raise ConnectionError("Proxy requires username/password authentication, but none provided")

                self.logger.debug("Client is authorizing")
                auth_ok = await session.cipher.client_auth_userpass(username, password, reader, writer)
                if not auth_ok:
                    raise ConnectionError("Authentication failed")
                self.logger.info("Authenticated successfully")

            elif method_chosen == 0x00:
                self.logger.info("No authentication required by proxy")

            else:
                raise ConnectionError(f"Unsupported authentication method selected by proxy: {method_chosen}")

            self.logger.debug("Handshaked")
            session.cipher.is_handshaked = True
            return session
        except Exception as ex:
            self.logger.error(ex)
            raise ex


    async def connect(self, target_host: str, target_port: int,
                            proxy_host: str = '127.0.0.1', proxy_port: int = 1080,
                            username: Optional[str] = None, password: Optional[str] = None) -> 'TCP_ProxySession':

        session = await self.handshake(proxy_host=proxy_host, proxy_port=proxy_port,
                                           username=username, password=password)

        cmd_bytes = await session.cipher.client_command(
            self.socks_version, self.user_commands['connect'], target_host, target_port
        )
        await session.asend(cmd_bytes, encrypt=False, log_bytes=False)
        address, port = await session.cipher.client_connect_confirm(session.reader)

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
        await session.asend(cmd_bytes, encrypt=False, log_bytes=False)
        udp_host, udp_port = await session.cipher.client_connect_confirm(session.reader)
        udp_session = await UDP_ProxySession.create(udp_host, udp_port, self.udp_cipher.copy())

        self.logger.debug(f"Got an associated UDP server {udp_session.host}:{udp_session.port} through proxy")
        return udp_session, session


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
        self.cipher = cipher
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


    async def close(self):
        self.writer.close()
        await self.writer.wait_closed()
        self.closed = True
        self.logger.debug(f"{self.client} session closed to {self.addr}")

    async def __aenter__(self):
        return self
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()

    def __str__(self):
        return f'{self.__class__.__name__}(host={self.host}, port={self.port})'

class UDP_ProxySession(asyncio.DatagramProtocol):
    def __init__(self, cipher: 'Cipher'):
        self.transport = None
        self.recv_queue = asyncio.Queue()
        self.logger = logging.getLogger(__name__)
        self.host = 'N/A'
        self.port = 0
        self.cipher = cipher

        self.client_ip = 'N/A'
        self.client_port = 0
        self.addr = f'{self.host}:{self.port}'


    def send(self, data: bytes):
        header_socks5 = self.format_socks5_udp_header(self.host, self.port)
        self.raw_send(b''.join(self.cipher.encrypt(header_socks5 + data)))
        self.logger.debug(f"Sent {len(data)} bytes to UDP proxy {self.addr}")

    async def recv(self, timeout: int = 5) -> Tuple[bytes, Tuple[str, int]]:
        data = await asyncio.wait_for(self.raw_recv(), timeout=timeout)
        self.logger.debug(f"Readed {len(data)} bytes from UDP proxy {self.addr}")
        return self.cipher.decrypt(data[0]), data[1]


    def format_socks5_udp_header(self, host: str, port: int) -> bytes:
        rsv = 0
        frag = 0

        try: # IPv(4/6)
            ip = ipaddress.ip_address(host)
            if ip.version == 4:
                atyp = 1  # IPv4
                addr_bytes = ip.packed  # 4 байта
            else:
                atyp = 4  # IPv6
                addr_bytes = ip.packed  # 16 байт
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
        raise ConnectionError(f"{self} error: {exc}")

    def connection_lost(self, exc):
        raise ConnectionError(f"{self} connection with {self.client_ip}:{self.client_port} closed")

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
    async def create(host: str, port: int, cipher: 'Cipher') -> 'UDPClient':
        loop = asyncio.get_running_loop()
        transport, protocol = await loop.create_datagram_endpoint(
            lambda: UDP_ProxySession(cipher),
            remote_addr=(host, port)
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


class Socks5_UDP_Retranslator(UDPServerProxy):
    def __init__(self, remote_host: str, remote_port: int, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.remote_host = remote_host
        self.remote_port = remote_port

    def datagram_received(self, data: bytes, addr: Tuple[str, int]):
        self.last_activity = time.time()
        self.logger.debug(f"{self} datagram from {addr}")

        if self.client_addr is None:
            self.client_addr = addr

        try:
            if addr == self.client_addr: # from client
                self.transport.sendto(self.cipher.encrypt(data), (self.remote_host, self.remote_port))
                self.logger.debug(
                    f"{self.client_addr}->UDP->{self.remote_host}:{self.remote_port} translated {len(data)} bytes"
                )
            elif self.client_addr: # from server
                self.transport.sendto(self.cipher.decrypt(data), self.client_addr)
                self.logger.debug(
                    f"{self.client_addr}<-UDP<-{self.remote_host}:{self.remote_port} translated {len(data)} bytes"
                )

        except Exception as e:
            self.logger.error(f"UDP relay error: {e}")

class Socks5_TCP_Retranslator(Socks5Client):
    def __init__(self, remote_host: str, remote_port: int, username: str = '', password: str = '', *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.remote_host = remote_host
        self.remote_port = remote_port
        self.username = username
        self.password = password
        self.pipe = Socks5Server.pipe

        self._local_host = 'localhost'
        self._local_host = 0

        self.local_server = None

    async def async_listen_and_forward(self, local_host: str = '127.0.0.1', local_port: int = 1080,
                                       log_bytes: bool = False):
        try:
            self.local_server = Socks5Server(host=local_host, port=local_port, accept_anonymous=True, users={'u':'pw'})
            self.local_server.handle_client = self.handle_local_client
            self.logger.info(f"Retranslator started at {local_host}:{local_port} for {self.remote_host}:{self.remote_port}")

            self._local_host = self.local_server.host
            self._local_host = self.local_server.port

            await self.local_server.start()
        except KeyboardInterrupt:
            self.logger.info('Client closed')

    def listen_and_forward(self, *args, **kwargs):
        try:
            asyncio.run(self.async_listen_and_forward(*args, **kwargs))
        except KeyboardInterrupt:
            self.logger.info('Client closed')
        except (ConnectionResetError, OSError):
            self.logger.info('Server closed')

    async def handle_local_client(self, client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter):
        default_cipher = self.local_server.ciphers[0].copy()

        # Connecting to the local proxy, getting a command
        self.logger.debug('Local client connecting...')
        try:
            user = await self.local_server.handshake(client_reader, client_writer, default_cipher)
        except Exception as e:
            self.logger.error(
                f"Can not do handshake to local proxy {self.local_server.host}:{self.local_server.port} — {e}"
            )
            client_writer.close()
            await client_writer.wait_closed()
            return
        self.logger.info(f'Local client connected {user}')
        addr, port, command = await default_cipher.server_handle_command(
            self.socks_version, self.local_server.user_commands, client_reader
        )
        self.logger.info(f'Local client {user} sent command {command.__qualname__}')

        # Connecting to the remote proxy, sending command
        try:
            remote_session = await self.handshake(
                proxy_host=self.remote_host, proxy_port=self.remote_port, username=self.username, password=self.password
            )
        except ConnectionRefusedError:
            self.logger.error(f"The server is not started {self.remote_host}:{self.remote_port}")
            client_writer.close()
            await client_writer.wait_closed()
            return
        except Exception as e:
            self.logger.error(f"Can not do handshake to remote proxy {self.remote_host}:{self.remote_port} — {e}")
            client_writer.close()
            await client_writer.wait_closed()
            return
        self.logger.debug(f'Client {user} handshaked with remote server')


        if command == ConnectionMethods.CONNECT:
            cmd_bytes = await remote_session.cipher.client_command(
                self.socks_version, self.user_commands['connect'], addr, port
            )
            await remote_session.asend(cmd_bytes, encrypt=False, log_bytes=False)
            address, port = await remote_session.cipher.client_connect_confirm(remote_session.reader)

            self.logger.debug(f"Establishing TCP connection to {addr}:{port}...")

            try:
                local_ip, local_port = remote_session.writer.get_extra_info("sockname")
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
                client_writer.write(b''.join(reply_frames))
                await client_writer.drain()
                return

            stop_event = asyncio.Event()
            try:
                await asyncio.gather(
                    self.pipe(self, client_reader, remote_session.writer, stop_event, encrypt=remote_session.cipher.encrypt,
                              name='client -> server'),
                    self.pipe(self, remote_session.reader, client_writer, stop_event, decrypt=remote_session.cipher.decrypt,
                              name='client <- server'),
                )
            except (ConnectionResetError, OSError):
                pass
            self.logger.debug(f"TCP connection to {addr}:{port} is closed")


        elif command == ConnectionMethods.UDP_ASSOCIATE:
            self.logger.debug("Starting UDP server...")
            cmd_bytes = await remote_cipher.client_command(
                self.socks_version, self.user_commands['associate'], addr, port
            )
            await remote_session.asend(cmd_bytes, encrypt=False, log_bytes=False)
            address, port = await remote_session.cipher.client_connect_confirm(reader)

            self.logger.debug(f"Establishing UDP connection to {address}:{port}...")
            loop = asyncio.get_running_loop()

            try:
                udp_session = Socks5_UDP_Retranslator.create(remote_session.cipher)
            except Exception as e:
                self.logger.error(f"Failed to start UDP relay: {e}")
                reply = await cipher.server_make_reply(self.socks_version, REPLYES_CODES['failure'], '0.0.0.0', 0)
                client_writer.write(reply)
                await client_writer.drain()
                return 1

            udp_host, udp_port = udp_session.transport.get_extra_info('sockname')
            udp_host = '127.0.0.1' if udp_host == '0.0.0.0' else udp_host
            self.logger.info(f"Started UDP server for {addr}:{port} at {udp_host}:{udp_port}")

            try:
                reply = await default_cipher.server_make_reply(self.socks_version, REPLYES_CODES['succeeded'], udp_host, udp_port)
                client_writer.write(reply)
                await client_writer.drain()
            except Exception as e:
                self.logger.warning(f"Failed to make UDP connection at TCP {addr}:{port}; UDP {udp_host}:{udp_port} => {e}")
                client_writer.write(await default_cipher.server_make_reply(self.socks_version, REPLYES_CODES['failure'], '0.0.0.0', 0))
                await client_writer.drain()
                return

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

                        await asyncio.sleep(.5)
                    except Exception as e:
                        self.logger.warning(f"UDP_ASSOCIATE TCP connection error: {e}")
                        break
            finally:
                udp_session.close()


        elif command == ConnectionMethods.BIND:
            cmd_bytes = await remote_cipher.client_command(
                self.socks_version, self.user_commands['bind'], addr, port
            )
            await remote_session.asend(cmd_bytes, encrypt=False, log_bytes=False)
            address, port = await remote_session.cipher.client_connect_confirm(reader)