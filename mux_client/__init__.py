from typing import *
import asyncio
import struct
import itertools

from ..base_cipher import Cipher
from ..proxy_client import Socks5Client, Socks5_TCP_Retranslator, TCP_ProxySession


class MuxStream:
    def __init__(self, mux: "MuxSession", stream_id: int, cipher: Cipher):
        self.mux = mux
        self.cipher = cipher
        self.stream_id = stream_id
        self.queue = asyncio.Queue()
        self.closed = False

    async def asend(self, data: bytes, encrypt: bool = True):
        if self.closed:
            raise ConnectionError("Stream is closed")

        if encrypt:
            for frame in self.cipher.encrypt(data):
                await self.mux._send_frame(self.stream_id, 0x00, frame)
        else:
            await self.mux._send_frame(self.stream_id, 0x00, data)

    async def drain(self):
        await self.mux._drain()

    async def arecv(self) -> Optional[bytes]:
        if self.closed:
            return None
        data = await self.queue.get()
        if data is None:
            self.closed = True
        return b''.join(self.cipher.decrypt(data))

    def get_sockname(self) -> Tuple[str, int]:
        return self.mux.writer.get_extra_info("sockname")

    async def close(self):
        if not self.closed:
            await self.mux._send_frame(self.stream_id, 0x01, b"")  # FIN
            self.queue.put_nowait(None)
            self.closed = True

class TCP_MuxSession:
    HEADER_STRUCT = struct.Struct("!IBI")
    # stream_id (4 bytes), flags (1 byte), length (4 bytes)

    def __init__(self, client: Socks5Client, tcp_session: TCP_ProxySession, host: str, port: int,
                 username: str = '', password: str = '', mux_name: str = 'Mux', log_bytes: bool = False):

        self.mux_name = mux_name
        self.client = client
        self.tcp_session = tcp_session
        self.reader = self.tcp_session.reader
        self.writer = self.tcp_session.writer
        self.cipher = self.tcp_session.cipher

        self.host = host
        self.port = port
        self.username = username
        self.password = password

        self.log_bytes = log_bytes
        self.streams: Dict[int, MuxStream] = {}
        self.closed = False
        self._id_iter = itertools.count(1)  # stream_id
        self._reader_task = asyncio.create_task(self._read_loop())
        self._writer_lock = asyncio.Lock()

    async def open_stream(self) -> MuxStream:
        stream_id = next(self._id_iter)
        stream = MuxStream(self, stream_id, self.cipher.copy())
        self.streams[stream_id] = stream
        return stream

    async def _send_frame(self, stream_id: int, flags: int, payload: bytes):
        async with self._writer_lock:
            self.writer.write(self.HEADER_STRUCT.pack(stream_id, flags, len(payload)) + payload)

    async def _drain(self):
        await self.writer.drain()

    async def _read_loop(self):
        try:
            while not self.closed:
                header = await self.reader.readexactly(self.HEADER_STRUCT.size)
                stream_id, flags, length = self.HEADER_STRUCT.unpack(header)
                payload = await self.reader.readexactly(length) if length > 0 else b""

                stream = self.streams.get(stream_id)
                if not stream:
                    continue

                if flags & 0x01:  # FIN
                    stream.queue.put_nowait(None)
                    stream.closed = True
                    self.streams.pop(stream_id, None)
                else:
                    stream.queue.put_nowait(payload)
        except asyncio.IncompleteReadError:
            await self.close()

    async def close(self):
        if self.closed:
            return
        self.closed = True
        self._reader_task.cancel()
        try:
            await self._reader_task
        except asyncio.CancelledError:
            pass
        for stream in list(self.streams.values()):
            stream.queue.put_nowait(None)
        self.streams.clear()
        try:
            self.writer.close()
            await self.writer.wait_closed()
        except:
            pass


class Socks5_TCP_Mux_Retranslator(Socks5_TCP_Retranslator):
    def __init__(self, *args, mux_workers: int = 1, **kwargs):
        super().__init__(*args, **kwargs)
        self.mux_workers = mux_workers
        self.mux_sessions = []

    async def async_listen_and_forward(self, local_host: str = '127.0.0.1', local_port: int = 1080):
        for i in range(self.mux_workers):
            tcp_session = await self.handshake(
                proxy_host=self.remote_host, proxy_port=self.remote_port, username=self.username, password=self.password
            )
            self.mux_sessions.append(
                TCP_MuxSession(self, tcp_session, self.remote_host, self.remote_port, mux_name=f'MuxSession{i}')
            )
        super().async_listen_and_forward(local_host=local_host, local_port=local_port)

    async def handle_local_client(self, client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter):
        try:
            addr, port, command, default_cipher = await self.listen_local_cmd(client_reader, client_writer)
        except Exception as e:
            self.logger.error(
                f"Can not do handshake to local proxy {self.local_server.host}:{self.local_server.port} — {e}"
            )
            return

        try:
            remote_stream = await self.mux_sessions[0].open_stream() # Потом надо распределить и открывать стрим в самой незабитой сессии
            self.logger.debug('Client handshaked with remote server')
        except ConnectionRefusedError:
            self.logger.error(f"Can not connect to remote proxy {self.remote_host}:{self.remote_port}")
            return
        except Exception as e:
            self.logger.error(f"Can not do handshake to remote proxy {self.remote_host}:{self.remote_port} — {e}")
            return

        try:
            status_code = await command(addr, port, default_cipher, remote_stream, client_reader, client_writer)
            self.logger.debug(f"Connection to {addr}:{port} is closed, code: {status_code}")
            await self.close_writer(client_writer)
        except Exception as e:
            self.logger.error(f"Running client cmd error {self.remote_host}:{self.remote_port} — {e}")
            return

    async def mux_pipe(self, client: Union[asyncio.StreamWriter, asyncio.StreamReader], remote_session: MuxStream,
                       name: str = 'default', encrypt: Optional[callable] = None, decrypt: Optional[callable] = None,
                       timeout: int = 300) -> Tuple[int, int]:
        try:
            bytes_received = 0
            bytes_sent = 0
            buffer = bytearray()
            to_remote = isinstance(client, asyncio.StreamReader)

            loop_con = (lambda: not client.at_eof()) if to_remote else (lambda: not remote_session.closed)
            read_bytes = (lambda: client.read(4096)) if to_remote else remote_session.arecv()

            while loop_con():
                data = await asyncio.wait_for(read_bytes(), timeout=timeout)
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
                    if to_remote:
                        await remote_session.asend(frame)
                    else:
                        client.write(frame)
                        await client.drain()

                    bytes_sent += len(frame)
                    if self.log_bytes:
                        self.bytes_sent += len(frame)

        except asyncio.TimeoutError:
            pass
        except asyncio.CancelledError:
            pass
        except Exception as e:
            self.logger.error(f"Proxying PIPE '{name}' error: {repr(e)}")

        return bytes_sent, bytes_received


    async def client_confirm_cmd(self, remote_session: MuxStream) -> Tuple[str, int]:
        data = await remote_session.arecv()
        ver, rep, rsv, atyp = data[:4]

        if ver != 0x05:
            raise ConnectionError(f"Invalid SOCKS version in reply: {ver}")
        if rep != 0x00:
            raise ConnectionError(f"SOCKS5 request failed {REPLYES[rep]}")

        if atyp == 0x01:  # IPv4
            address = socket.inet_ntoa(data[4:8])
            port_bytes = data[8:10]
        elif atyp == 0x03:  # Domain
            domain_len = int.from_bytes(data[4])
            address = data[5:5+domain_len].decode('idna')
            port_bytes = data[5+domain_len:5+domain_len+2]
        elif atyp == 0x04:  # IPv6
            address = socket.inet_ntoa(data[4:20])
            port_bytes = data[20:22]
        else:
            raise ConnectionError(f"Invalid ATYP in reply: {atyp}")

        return address, struct.unpack('!H', port_bytes)[0]


    async def CONNECT(self, addr: str, port: int, default_cipher: Cipher, remote_session: MuxStream,
                      client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter) -> int:
        if not (await self.filter_addr(addr, port)):
            return 1

        cmd_bytes = await remote_session.cipher.client_command(
            self.socks_version, self.user_commands['connect'], addr, port
        )
        await remote_session.asend(cmd_bytes)
        try:
            address, port = await self.client_connect_confirm(remote_session)
        except ConnectionError as e:
            self.logger.error(e)
            return 1

        self.logger.debug(f"Establishing TCP connection to {addr}:{port}...")

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

        try:
            t1 = asyncio.create_task(self.mux_pipe(self, client_reader, remote_session,
                                               encrypt=remote_session.cipher.encrypt, name='client -> server'))
            t2 = asyncio.create_task(self.mux_pipe(self, client_writer, remote_session,
                                               decrypt=remote_session.cipher.decrypt, name='client <- server'))
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

        return 0