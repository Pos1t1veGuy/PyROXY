from typing import *
import asyncio
import socket
import logging
import ipaddress
import struct

from .logger_setup import *
from .base_cipher import Cipher
from .proxy_server import Socks5Server, ConnectionMethods, UDPServerProxy


class Socks5Client:
    def __init__(self, cipher: Optional[Cipher] = None, udp_cipher: Optional[Cipher] = None,  log_bytes: bool = False):
        self.socks_version = 5
        self.default_cipher = Cipher() if cipher is None else cipher
        self.default_udp_cipher = Cipher() if udp_cipher is None else udp_cipher
        self.log_bytes = log_bytes # only after handshake
        self.udp_socket = None
        self.reader: Optional[asyncio.StreamReader] = None
        self.writer: Optional[asyncio.StreamWriter] = None
        self.connected = False
        self.bytes_sent = 0
        self.bytes_received = 0
        self.logger = logging.getLogger(__name__)

        self.default_cipher.is_client = True
        self.default_udp_cipher.is_client = True

        self.user_commands = {
            'connect': 0x01,
            'bind': 0x02,
            'associate': 0x03,
        }
        self.cipher = self.default_cipher.copy()
        self.udp_cipher = self.default_udp_cipher.copy()
        self._host = None
        self._port = None
        self._proxy_host = None
        self._proxy_port = None
        self._udp_proxy_host = None
        self._udp_proxy_port = None
        self._loop = asyncio.new_event_loop()
        self._pt_buffer = bytearray()
        asyncio.set_event_loop(self._loop)

    async def handshake(self, proxy_host: str = '127.0.0.1', proxy_port: int = 1080,
                        username: Optional[str] = None, password: Optional[str] = None):
        self.reader, self.writer = await asyncio.open_connection(proxy_host, proxy_port)
        self.logger.info(
            f"Connected to SOCKS5 proxy at {proxy_host}:{proxy_port} using cipher {self.cipher.__class__.__name__}"
        )

        self.cipher = self.default_cipher.copy()
        self.udp_cipher = self.default_udp_cipher.copy()
        await self.cipher.client_hello(self, self.reader, self.writer)
        self.logger.debug("Sent client_hello")

        methods = [0x00]
        if username and password:
            methods.insert(0, 0x02)

        methods_msg = await self.cipher.client_send_methods(self.socks_version, methods)
        await self.asend(methods_msg, encrypt=False, log_bytes=False)
        method_chosen = await self.cipher.client_get_method(self.socks_version, self.reader)
        self.logger.debug("Sent client_hello")

        try:
            if method_chosen == 0xFF:
                raise ConnectionError("No acceptable authentication methods.")

            if method_chosen == 0x02:
                if not username or not password:
                    raise ConnectionError("Proxy requires username/password authentication, but none provided")

                auth_ok = await self.cipher.client_auth_userpass(username, password, self.reader, self.writer)
                if not auth_ok:
                    raise ConnectionError("Authentication failed")
                self.logger.info("Authenticated successfully")

            elif method_chosen == 0x00:
                self.logger.info("No authentication required by proxy")

            else:
                raise ConnectionError(f"Unsupported authentication method selected by proxy: {method_chosen}")

            self.logger.debug("Handshaked")
        except Exception as ex:
            self.logger.error(ex)
            raise ex


    async def async_connect(self, target_host: str, target_port: int,
                            proxy_host: str = '127.0.0.1', proxy_port: int = 1080,
                            username: Optional[str] = None, password: Optional[str] = None):

        await self.handshake(proxy_host=proxy_host, proxy_port=proxy_port, username=username, password=password)

        cmd_bytes = await self.cipher.client_command(
            self.socks_version, self.user_commands['connect'], target_host, target_port
        )
        await self.asend(cmd_bytes, encrypt=False, log_bytes=False)
        address, port = await self.cipher.client_connect_confirm(self.reader)

        self._host = target_host
        self._port = target_port
        self._proxy_host = proxy_host
        self._proxy_port = proxy_port
        self.connected = True
        self.logger.debug(f"Connected to {target_host}:{target_port} through proxy")

    def connect(self, target_host: str, target_port: int,
                proxy_host: str = '127.0.0.1', proxy_port: int = 1080,
                username: Optional[str] = None, password: Optional[str] = None):
        return self._loop.run_until_complete(self.async_connect(target_host, target_port,
                                    proxy_host=proxy_host, proxy_port=proxy_port, username=username, password=password))

    async def async_udp_associate(self, target_host: str, target_port: int,
                            proxy_host: str = '127.0.0.1', proxy_port: int = 1080,
                            username: Optional[str] = None, password: Optional[str] = None) -> Tuple[str, str]:

        await self.handshake(proxy_host=proxy_host, proxy_port=proxy_port, username=username, password=password)

        cmd_bytes = await self.cipher.client_command(
            self.socks_version, self.user_commands['associate'], target_host, target_port
        )
        await self.asend(cmd_bytes, encrypt=False, log_bytes=False)

        udp_host, udp_port = await self.cipher.client_connect_confirm(self.reader)

        self._host = target_host
        self._port = target_port
        self._udp_proxy_host = udp_host
        self._udp_proxy_port = udp_port
        self._proxy_host = proxy_host
        self._proxy_port = proxy_port
        self.udp_socket = await self._get_udp_socket(udp_host, udp_port)

        self.logger.debug(f"Got an associated UDP server {udp_host}:{udp_port} through proxy")
        return udp_host, udp_port

    def udp_associate(self, target_host: str, target_port: int,
                proxy_host: str = '127.0.0.1', proxy_port: int = 1080,
                username: Optional[str] = None, password: Optional[str] = None):
        return self._loop.run_until_complete(self.async_udp_associate(target_host, target_port,
                                    proxy_host=proxy_host, proxy_port=proxy_port, username=username, password=password))

    async def _get_udp_socket(self, udp_host: str, udp_port: int) -> 'UDPClient':
        loop = asyncio.get_running_loop()
        transport, protocol = await loop.create_datagram_endpoint(
            lambda: UDPClient(),
            remote_addr=(udp_host, udp_port)
        )
        protocol._transport = transport
        return protocol


    async def asend(self, data: bytes, encrypt: bool = True, log_bytes: bool = True, wait: bool = True):
        data = self.cipher.encrypt(data) if encrypt else data
        if self.log_bytes and log_bytes:
            self.bytes_sent += len(data)
        self.writer.write(data)
        if wait:
            await self.writer.drain()
        self.logger.debug(f"Sent {len(data)} bytes to TCP proxy {self._proxy_host}:{self._proxy_port}")

    def send(self, data: bytes, encrypt: bool = True):
        return self._loop.run_until_complete(self.asend(data, encrypt=encrypt))


    async def aread(self, num_bytes: int = -1, decrypt: bool = True,
                    log_bytes: bool = True, **kwargs) -> bytes:
        # "num_bytes == -1" - means that aread will return every byte before the connection is closed

        if num_bytes < -1 or num_bytes == 0:
            return b''

        buffer_length = len(self._pt_buffer)
        if num_bytes == -1:
            data = await self.reader.read(-1)
            if self.log_bytes and log_bytes:
                self.bytes_received += len(data)
            data = self._pt_buffer + (self.cipher.decrypt(data, **kwargs) if decrypt and data else data)
            self._pt_buffer = bytearray()
        elif num_bytes == buffer_length:
            data = self._pt_buffer
            self._pt_buffer = bytearray()
        elif num_bytes > buffer_length:
            data = await self.reader.read(num_bytes - buffer_length)
            if self.log_bytes and log_bytes:
                self.bytes_received += len(data)
            data = self._pt_buffer + (self.cipher.decrypt(data, **kwargs) if decrypt and data else data)
            self._pt_buffer = bytearray()
        else:
            data = self._pt_buffer[:num_bytes]
            del self._pt_buffer[:num_bytes]

        self.logger.debug(f"Readed {len(data)} bytes from TCP proxy {self._proxy_host}:{self._proxy_port}")
        return data

    def read(self, num_bytes: int = -1, **kwargs) -> bytes:
        return self._loop.run_until_complete(self.aread(num_bytes, **kwargs))

    async def areadexactly(self, num_bytes: int, decrypt: bool = True, log_bytes: bool = True, **kwargs) -> bytes:
        buffer_length = len(self._pt_buffer)
        if num_bytes == buffer_length:
            data = self._pt_buffer
            self._pt_buffer = bytearray()
        elif num_bytes > buffer_length:
            data = await self.reader.readexactly(num_bytes - buffer_length)
            if self.log_bytes and log_bytes:
                self.bytes_received += len(data)
            data = self._pt_buffer + (self.cipher.decrypt(data, **kwargs) if decrypt else data)
            self._pt_buffer = bytearray()
        else:
            data = self._pt_buffer[:num_bytes]
            del self._pt_buffer[:num_bytes]

        self.logger.debug(f"Readed {len(data)} bytes from TCP proxy {self._proxy_host}:{self._proxy_port}")
        return data

    def readexactly(self, num_bytes: int, **kwargs) -> bytes:
        return self._loop.run_until_complete(self.areadexactly(num_bytes, **kwargs))

    async def areaduntil(self, sep: Union[str, bytes] = '\n', decrypt: bool = True, log_bytes: bool = True,
                         bytes_block: int = 1024, limit: int = 65535, **kwargs) -> bytes:
        sep = sep.encode() if isinstance(sep, str) else sep

        pos = self._pt_buffer.find(sep)
        if pos != -1:
            data = self._pt_buffer[:pos + len(sep)]
            del self._pt_buffer[:pos + len(sep)]
            self.logger.debug(f"Readed {len(data)} bytes from TCP proxy {self._proxy_host}:{self._proxy_port}")
            return data

        if not decrypt:
            try:
                data = await (self.reader.readline() if sep == b'\n' else self.reader.readuntil(sep))
            except asyncio.IncompleteReadError as e:
                data = e.partial
            if self.log_bytes and log_bytes:
                self.bytes_received += len(data)
                self.logger.debug(
                    f"Readed {len(self._pt_buffer + data)} bytes from TCP proxy {self._proxy_host}:{self._proxy_port}"
                )
            return self._pt_buffer + data

        while True:
            chunk = await self.reader.read(bytes_block)
            if not chunk:
                break

            if self.log_bytes and log_bytes:
                self.bytes_received += len(chunk)

            self._pt_buffer += self.cipher.decrypt(chunk, **kwargs)

            pos = self._pt_buffer.find(sep)
            if pos != -1:
                data = self._pt_buffer[:pos + len(sep)]
                del self._pt_buffer[:pos + len(sep)]
                self.logger.debug(f"Readed {len(data)} bytes from TCP proxy {self._proxy_host}:{self._proxy_port}")
                return data

        data = self._pt_buffer
        self._pt_buffer = bytearray()
        self.logger.debug(f"Readed {len(data)} bytes from TCP proxy {self._proxy_host}:{self._proxy_port}")
        return data

    def readuntil(self, **kwargs) -> bytes:
        return self._loop.run_until_complete(self.areaduntil(**kwargs))

    async def areadline(self, log_bytes: bool = True, decrypt: bool = True, **kwargs) -> bytes:
        if 'sep' in kwargs.keys():
            kwargs.pop('sep')
        return await self.areaduntil(sep='\n', decrypt=decrypt, log_bytes=log_bytes, **kwargs)

    def readline(self, **kwargs) -> bytes:
        return self._loop.run_until_complete(self.areadline(**kwargs))


    async def udp_send(self, data: bytes):
        self.logger.debug(f"Sent {len(data)} bytes to UDP proxy {self._udp_proxy_host}:{self._udp_proxy_port}")
        return self.udp_send(data)

    def udp_send(self, data: bytes):
        if self.udp_socket:
            header_socks5 = self.format_socks5_udp_header(self._udp_proxy_host, self._udp_proxy_port)
            self.udp_socket.send(self.udp_cipher.encrypt(header_socks5 + data))
        else:
            raise ConnectionError(
        f'The client should have connected to the SOCKS5 proxy and executed the UDP ASSOCIATE command, but did not do so'
            )

    async def async_udp_recv(self, timeout: int = 5) -> Tuple[bytes, Tuple[str, int]]:
        data = await asyncio.wait_for(self.udp_socket.recv(), timeout=timeout)
        self.logger.debug(f"Readed {len(data)} bytes from UDP proxy {self._udp_proxy_host}:{self._udp_proxy_port}")
        return self.udp_cipher.decrypt(data[0]), data[1]

    def udp_recv(self, timeout: int = 5) -> Tuple[bytes, Tuple[str, int]]:
        return self._loop.run_until_complete(self.udp_recv(timeout=timeout))


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


    async def async_close(self):
        if self.writer:
            self.writer.close()
            await self.writer.wait_closed()
            self.connected = False
            self.logger.info("Connection closed.")

    def close(self):
        self._loop.run_until_complete(self.async_close())
        self._loop.stop()
        self._loop.close()

    async def __aenter__(self):
        return self
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.async_close()

    def __enter__(self):
        return self
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def __str__(self):
        connection = f'connected="{self._host}:{self._port}" proxy="{self._proxy_host}:{self._proxy_port}"'
        return f'{self.__class__.__name__}({connection if self.connected else "waiting"}, cipher={self.cipher})'


class UDPClient(asyncio.DatagramProtocol):
    def __init__(self):
        self.transport = None
        self.recv_queue = asyncio.Queue()
        self.logger = logging.getLogger(__name__)
        self.host = 'N/A'
        self.port = 0

        self.client_ip = 'N/A'
        self.client_port = 0

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

    def send(self, data: bytes):
        if self.transport is not None:
            self.transport.sendto(data)

    async def recv(self):
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
    async def create(host: str, port: int) -> 'UDPClient':
        loop = asyncio.get_running_loop()
        transport, protocol = await loop.create_datagram_endpoint(
            lambda: UDPClient(),
            remote_addr=(host, port)
        )
        protocol._transport = transport
        protocol.host, protocol.port = protocol._transport.transport.get_extra_info('sockname')
        return protocol

    async def __aenter__(self):
        return self
    async def __aexit__(self, exc_type, exc, tb):
        self.close()


    def __str__(self):
        return f'{self.__class__.__name__}(host="{self.host}", port={self.port})'


class UDPServerProxyListener(UDPServerProxy):
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


class Socks5Listener(Socks5Client):
    def __init__(self, remote_host: str, remote_port: int, username: str = '', password: str = '', *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.remote_host = remote_host
        self.remote_port = remote_port
        self.username = username
        self.password = password

        self._local_host = 'localhost'
        self._local_host = 0

        self.local_server = None

    async def async_listen_and_forward(self, local_host: str = '127.0.0.1', local_port: int = 1080,
                                       log_bytes: bool = False):
        self.local_server = Socks5Server(host=local_host, port=local_port, accept_anonymous=True)
        self.local_server.handle_client = self.handle_local_client
        self.logger.info(f"Retranslator started at {local_host}:{local_port} for {self.remote_host}:{self.remote_port}")

        self._local_host = self.local_server.host
        self._local_host = self.local_server.port

        await self.local_server.async_start()

    async def handle_local_client(self, client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter):
        default_cipher = self.local_server.cipher.copy()

        # Connecting to the local proxy, getting a command
        self.logger.debug('Local client connecting...')
        user = await self.local_server.handshake(client_reader, client_writer, default_cipher)
        try:
            ...
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
            await self.handshake(proxy_host=self.remote_host, proxy_port=self.remote_port,
                                 username=self.username, password=self.password)
            remote_reader, remote_writer = self.reader, self.writer
            remote_cipher = self.cipher
        except Exception as e:
            self.logger.error(f"Can not do handshake to remote proxy {self.remote_host}:{self.remote_port} — {e}")
            client_writer.close()
            await client_writer.wait_closed()
            return
        self.logger.debug(f'Client {user} handshaked with remote server')


        if command == ConnectionMethods.CONNECT:
            cmd_bytes = await remote_cipher.client_command(
                self.socks_version, self.user_commands['connect'], addr, port
            )
            await self.asend(cmd_bytes, encrypt=False, log_bytes=False)
            address, port = await remote_cipher.client_connect_confirm(remote_reader)

            self.logger.debug(f"Establishing TCP connection to {addr}:{port}...")

            try:
                local_ip, local_port = remote_writer.get_extra_info("sockname")
                client_writer.write(await default_cipher.server_make_reply(self.socks_version, 0x00, local_ip, local_port))
                await client_writer.drain()
            except Exception as e:
                self.logger.warning(f"Failed to connect to {addr}:{port} => {e}")
                client_writer.write(await default_cipher.server_make_reply(self.socks_version, 0xFF, '0.0.0.0', 0))
                await client_writer.drain()
                return

            await asyncio.gather(
                self.pipe(client_reader, remote_writer, encrypt=remote_cipher.encrypt),  # client -> server
                self.pipe(remote_reader, client_writer, decrypt=remote_cipher.decrypt),  # client <- server
            )
            self.logger.debug(f"TCP connection to {addr}:{port} is closed")


        elif command == ConnectionMethods.UDP_ASSOCIATE:
            self.logger.debug("Starting UDP server...")
            cmd_bytes = await remote_cipher.client_command(
                self.socks_version, self.user_commands['associate'], addr, port
            )
            await self.asend(cmd_bytes, encrypt=False, log_bytes=False)
            address, port = await remote_cipher.client_connect_confirm(self.reader)

            self.logger.debug(f"Establishing UDP connection to {address}:{port}...")
            loop = asyncio.get_running_loop()

            try:
                transport, protocol = await loop.create_datagram_endpoint(
                    lambda: UDPServerProxyListener(self.remote_host, self.remote_port, self.local_server),
                    local_addr=('0.0.0.0', 0)
                )
            except Exception as e:
                self.logger.error(f"Failed to start UDP relay: {e}")
                reply = await cipher.server_make_reply(self.socks_version, 0x01, '0.0.0.0', 0)
                client_writer.write(reply)
                await client_writer.drain()
                return 1

            udp_host, udp_port = transport.get_extra_info('sockname')
            udp_host = '127.0.0.1' if udp_host == '0.0.0.0' else udp_host
            self.logger.info(f"Started UDP server for {addr}:{port} at {udp_host}:{udp_port}")

            try:
                reply = await cipher.server_make_reply(self.socks_version, 0x00, udp_host, udp_port)
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
                transport.close()


        elif command == ConnectionMethods.BIND:
            cmd_bytes = await remote_cipher.client_command(
                self.socks_version, self.user_commands['bind'], addr, port
            )
            await self.asend(cmd_bytes, encrypt=False, log_bytes=False)
            address, port = await remote_cipher.client_connect_confirm(self.reader)

    def listen_and_forward(self, *args, **kwargs):
        asyncio.run(self.async_listen_and_forward(*args, **kwargs))


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
                    data = decrypt(data)
                if encrypt:
                    data = encrypt(data)

                writer.write(data)
                if self.log_bytes:
                    self.bytes_sent += len(data)
                await writer.drain()
        except Exception as e:
            self.logger.error(f"Proxying error: {e}")
        finally:
            writer.close()
            await writer.wait_closed()