from typing import *
import time
import asyncio
import struct
import itertools

from ..base_cipher import Cipher


def run_async(coro):
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

    if loop.is_running():
        task = asyncio.create_task(coro)
        task.add_done_callback(lambda t: t.exception())
    else:
        loop.run_until_complete(coro)



class MuxStreamWriter:
    def __init__(self, stream: 'MuxStream', mux: 'MuxSession'):
        self.mux = mux
        self.stream = stream
        self._close_task: asyncio.Task | None = None

    async def awrite(self, data: bytes):
        if self.stream.closed:
            raise ConnectionError("Stream is closed")
        await self.mux._send_frame(self.stream.stream_id, 0x00, data)
    def write(self, data: bytes):
        run_async(self.awrite(data))

    async def drain(self):
        await self.mux._drain()

    async def aclose(self):
        await self.stream.close()
        self.stream.closed = True
    def close(self):
        if not self.closed:
            try:
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    self._close_task = asyncio.create_task(self.aclose())
                else:
                    loop.run_until_complete(self.aclose())
            except RuntimeError:
                # если цикла нет — создаём временный
                asyncio.run(self.aclose())

    async def wait_closed(self):
        if self._close_task is not None:
            await self._close_task
        elif not self.closed:
            await self.stream.wait_closed() if hasattr(self.stream, "wait_closed") else None

class MuxStreamReader:
    def __init__(self, stream: 'MuxStream', mux: 'MuxSession', max_queue=500):
        self.mux = mux
        self.stream = stream
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
                self._buffer = piece[need:] + self._buffer
                got += need
            else:
                chunks.append(piece)
                got += len(piece)
        return b''.join(chunks)

    async def read(self, n: int = -1) -> bytes:
        bytes_received = len(self._buffer)
        chunks = [self._buffer]
        piece = None

        while (n < 0) or (bytes_received < n):
            try:
                if bytes_received == 0:
                    piece = await self.queue.get()
                else:
                    piece = self.queue.get_nowait()
            except asyncio.QueueEmpty:
                piece = None

            if piece is None:
                break

            bytes_received += len(piece)
            chunks.append(piece)

        result_bytes = b''.join(chunks)
        if n > 0 and result_bytes:
            self._buffer = result_bytes[n:]
            return result_bytes[:n]

        self._buffer = b''
        return result_bytes

    def at_eof(self):
        return self.eof and self.queue.empty()

class MuxStream:
    def __init__(self, mux: "MuxSession", stream_id: int, cipher: Cipher, max_queue: int = 100):
        self.mux = mux
        self.cipher = cipher
        self.stream_id = stream_id
        self.reader = MuxStreamReader(self, mux, max_queue=max_queue)
        self.writer = MuxStreamWriter(self, mux)

        self.queue = asyncio.Queue()
        self.closed = False
        self.bytes_sent = 0
        self.bytes_received = 0

    async def asend(self, data: bytes, encrypt: bool = True, log_bytes: bool = True):
        if isinstance(data, (list, tuple)):
            for frame in data:
                await self.asend(frame, encrypt=encrypt, log_bytes=log_bytes)

        else:
            try:
                if encrypt:
                    for cryptoframe in self.cipher.encrypt(data):
                        self.writer.write(cryptoframe)
                else:
                    self.writer.write(data)
                self.bytes_sent += len(data)

                await self.writer.drain()
            except ConnectionResetError:
                await self.close()

    async def drain(self):
        await self.mux._drain()

    async def arecv(self) -> Optional[bytes]:
        if self.closed:
            raise ConnectionError("Stream is closed")

        data = await self.reader.read()
        self.bytes_received += len(data)
        if not data:
            self.closed = True
            await self.reader._feed_data(None)
            return b''

        return b''.join(self.cipher.decrypt(data))

    def get_sockname(self) -> Tuple[str, int]:
        return self.mux.writer.get_extra_info("sockname")

    async def close(self):
        if not self.closed:
            await self.mux._send_frame(self.stream_id, 0x01, b"")  # FIN
            await self.reader._feed_data(None)
            self.closed = True

    def __str__(self):
        return f"{self.__class__.__name__}(id={self.stream_id}, closed={self.closed})"
    def __repr__(self):
        return f"<{self.__class__.__name__} id={self.stream_id} closed={self.closed}>"

class TCP_MuxSession:
    HEADER_STRUCT = struct.Struct("!IBI")
    # stream_id (4 bytes), flags (1 byte), length (4 bytes)

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, cipher: Cipher, host: str, port: int,
                 mux_name: str = 'Mux', log_bytes: bool = False, create_new_streams_in_read_loop: bool = False,
                 handle_stream: Optional[Callable[[MuxStream], None]] = None, user: Optional['User'] = None,
                 start_reader: bool = True, always_alive: bool = False):

        self.create_time = time.time()
        self.last_activity_time = time.time()
        self.mux_name = mux_name
        self.reader = reader
        self.writer = writer
        self.cipher = cipher

        self.host = host
        self.port = port

        self.log_bytes = log_bytes
        self.always_alive = always_alive
        self.user = user
        self.create_new_streams_in_read_loop = create_new_streams_in_read_loop
        self.handle_stream = handle_stream
        self.streams: Dict[int, MuxStream] = {}
        self.closed = False
        self._id_iter = itertools.count(1)  # stream_id
        self._reader_task = asyncio.create_task(self.read_loop()) if start_reader else None
        self._writer_lock = asyncio.Lock()

    async def open_stream(self, stream_id: int = -1) -> MuxStream:
        self.last_activity_time = time.time()
        if stream_id == -1 or stream_id in self.streams.keys():
            stream_id = next(self._id_iter)
        stream = MuxStream(self, stream_id, self.cipher.copy())
        self.streams[stream_id] = stream
        return stream

    async def close_stream(self, stream_id: int):
        self.last_activity_time = time.time()
        await self.streams[stream_id].close()
        self.streams.pop(stream_id)

    async def _send_frame(self, stream_id: int, flags: int, payload: bytes):
        self.last_activity_time = time.time()
        try:
            async with self._writer_lock:
                self.writer.write(self.HEADER_STRUCT.pack(stream_id, flags, len(payload)) + payload)
        except (ConnectionResetError, BrokenPipeError) as e:
            self.logger.warning(f"_send_frame failed: {e} (stream {stream_id})")

    async def _drain(self):
        self.last_activity_time = time.time()
        await self.writer.drain()

    async def read_loop(self):
        try:
            while not self.closed:
                header = await self.reader.readexactly(self.HEADER_STRUCT.size)
                self.last_activity_time = time.time()
                stream_id, flags, length = self.HEADER_STRUCT.unpack(header)
                payload = await self.reader.readexactly(length) if length > 0 else b""

                stream = self.streams.get(stream_id)
                if not stream:
                    if not self.create_new_streams_in_read_loop:
                        continue
                    else:
                        stream = await self.open_stream(stream_id)
                        asyncio.create_task(self.handle_stream(stream))

                if flags & 0x01:  # FIN
                    await stream.reader._feed_data(None)
                    stream.closed = True
                    self.streams.pop(stream_id, None)
                else:
                    await stream.reader._feed_data(payload)
        except asyncio.IncompleteReadError:
            await self.close()

    async def close(self):
        self.last_activity_time = time.time()
        if self.closed:
            return
        self.closed = True
        if self._reader_task:
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

    @property
    def streams_count(self) -> int:
        return len(self.streams)
    @property
    def address_str(self) -> str:
        return f'{self.host}:{self.port}'
    @property
    def address(self) -> str:
        return (self.host, self.port)

    def __str__(self):
        return f"{self.__class__.__name__}(address={self.address} streams_count={self.streams_count}, closed={self.closed})"
    def __repr__(self):
        return f"<{self.__class__.__name__} address={self.address} streams_count={self.streams_count} closed={self.closed}>"