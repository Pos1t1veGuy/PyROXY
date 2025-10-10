from typing import *
import asyncio
import struct
import itertools

from ..base_cipher import Cipher
from ..proxy_client import Socks5Client, Socks5_TCP_Retranslator, TCP_ProxySession


class MuxStreamReader:
    def __init__(self, mux: 'MuxSession', stream_id: int, max_queue=100):
        self.mux = mux
        self.stream_id = stream_id
        self.queue = asyncio.Queue(maxsize=max_queue)
        self.eof = False
        self._buffer = b""

    async def _feed_data(self, data: Optional[bytes]):
        if data is None:
            self.eof = True
            await self.queue.put(None)
        else:
            await self.queue.put(data)

    async def readexactly(self, n: int) -> bytes:
        chunks = []
        got = 0

        if self._buffer:
            chunks.append(self._buffer[:n])
            got = len(chunks[0])
            self._buffer = self._buffer[n:]
            if got >= n:
                return b"".join(chunks)

        while got < n:
            piece = await self.queue.get()
            if not piece: # EOF
                raise asyncio.IncompleteReadError(b''.join(chunks), n)
            need = n - got
            if len(piece) > need:
                chunks.append(piece[:need])
                rest = piece[need:]
                self._buffer = rest + getattr(self, "_buffer", b"")
                got += need
            else:
                chunks.append(piece)
                got += len(piece)
        return b''.join(chunks)

    async def read(self, n: int = -1) -> bytes:
        if n < 0:
            data = await self.queue.get()
            return data if not data is None else b''
        return await self.readexactly(n)

    def at_eof(self):
        return self.eof and self.queue.empty()


class MuxStream:
    def __init__(self, mux: "MuxSession", stream_id: int, cipher: Cipher, max_queue: int = 100):
        self.mux = mux
        self.cipher = cipher
        self.stream_id = stream_id
        self.reader = MuxStreamReader(mux, stream_id, max_queue=max_queue)
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
            raise ConnectionError("Stream is closed")

        data = await self.reader.read()
        if not data:
            self.closed = True
        return b''.join(self.cipher.decrypt(data))

    def get_sockname(self) -> Tuple[str, int]:
        return self.mux.writer.get_extra_info("sockname")

    async def close(self):
        if not self.closed:
            await self.mux._send_frame(self.stream_id, 0x01, b"")  # FIN
            await self.reader._feed_data(None)
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

    async def close_stream(self, stream_id: int):
        await self.streams[stream_id].close()
        self.streams.pop(stream_id)

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
                    await stream.reader._feed_data(None)
                    stream.closed = True
                    self.streams.pop(stream_id, None)
                else:
                    await stream.reader._feed_data(payload)
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
            await stream.reader._feed_data(None)
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

        self.server_commands = {
            # 0x00: self.PING,
            0x01: self.CONNECT,
            0x02: self.BIND,
            0x03: self.UDP_ASSOCIATE,
        }

    async def async_listen_and_forward(self, local_host: str = '127.0.0.1', local_port: int = 1080):
        for i in range(self.mux_workers):
            tcp_session = await self.handshake(
                proxy_host=self.remote_host, proxy_port=self.remote_port, username=self.username, password=self.password
            )
            self.mux_sessions.append(
                TCP_MuxSession(self, tcp_session, self.remote_host, self.remote_port, mux_name=f'MuxSession{i}')
            )

        asyncio.create_task(self.monitor_mux())
        await super().async_listen_and_forward(local_host=local_host, local_port=local_port)


    async def monitor_mux(self):
        while True:
            for i, session in enumerate(list(self.mux_sessions)):
                if session.closed:
                    self.logger.warning(f"Reconnecting MUX {i}...")
                    tcp_session = await self.handshake(proxy_host=self.remote_host, proxy_port=self.remote_port,
                                                       username=self.username, password=self.password)
                    self.mux_sessions[i] = TCP_MuxSession(self, tcp_session, self.remote_host, self.remote_port,
                                                          mux_name=f"MuxSession{i}")
            await asyncio.sleep(3)

    async def handle_local_client(self, client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter):
        try:
            addr, port, command, default_cipher, user = await self.listen_local_cmd(client_reader, client_writer)
        except Exception as e:
            self.logger.error(
                f"Can not do handshake to local proxy {self.local_server.host}:{self.local_server.port} — {e}"
            )
            return

        try:
            remote_stream = await self.mux_sessions[0].open_stream() # Потом надо распределить и открывать стрим в самой незабитой сессии
            # mux = min(self.mux_sessions, key=lambda s: len(s.streams))
            # remote_stream = await mux.open_stream()
            self.logger.debug('Client handshaked with remote server')
        except ConnectionRefusedError:
            self.logger.error(f"Can not connect to remote proxy {self.remote_host}:{self.remote_port}")
            return
        except Exception as e:
            self.logger.error(f"Can not do handshake to remote proxy {self.remote_host}:{self.remote_port} — {e}")
            return

        # try:
        status_code = await command(user, addr, port, default_cipher, remote_stream, client_reader, client_writer)
        self.logger.debug(f"Connection to {addr}:{port} is closed, code: {status_code}")
        await self.close_writer(client_writer)
        # except Exception as e:
        #     self.logger.error(f"Running client cmd error {self.remote_host}:{self.remote_port} — {e}")
        #     return

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


    async def CONNECT(self, user: 'User', addr: str, port: int, default_cipher: Cipher, remote_session: MuxStream,
                      client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter) -> int:
        if not (await self.filter_addr(user, addr, port)):
            return 1

        cmd_bytes = await remote_session.cipher.client_command(
            self.socks_version, self.user_commands['connect'], addr, port
        )
        await self.trace_event(remote_session.asend(b''.join(cmd_bytes), encrypt=False), event_name='CLIENT_CMD_SEND')
        try:
            address, port = await self.trace_event(
                remote_session.cipher.client_connect_confirm(remote_session.reader), event_name='SERVER_CMD_CONFIRM'
            )
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
            t1 = asyncio.create_task(self.mux_pipe(client_reader, remote_session, encrypt=remote_session.cipher.encrypt,
                                                   name='client -> server'))
            t2 = asyncio.create_task(self.mux_pipe(client_writer, remote_session, decrypt=remote_session.cipher.decrypt,
                                                   name='client <- server'))
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