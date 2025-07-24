import asyncio
import base64
import struct
import hashlib
import os


class Wrapper: ...

class HTTP_WS_Wrapper(Wrapper):
    GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

    def __init__(self, path: str = "/", host: str = "example.com"):
        self.path = path
        self.host = host
        self._mask_offset = 0

    async def client_hello(self, client: 'Socks5Client', reader: asyncio.StreamReader, writer: asyncio.StreamWriter):

        key = base64.b64encode(os.urandom(16)).decode()
        http_get = (
            f"GET {self.path} HTTP/1.1\r\n"
            f"Host: {self.host}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            "\r\n"
        )
        writer.write(http_get.encode())
        await writer.drain()

        response = await reader.readuntil(b"\r\n\r\n")
        if b"101" not in response or b"Switching Protocols" not in response:
            raise ConnectionError(f"WebSocket handshake failed: {response!r}")

    async def server_hello(self, server: 'Socks5Server', user: 'User', reader: asyncio.StreamReader,
                           writer: asyncio.StreamWriter):
        request = await reader.readuntil(b"\r\n\r\n")
        if b"upgrade: websocket" not in request.lower():
            raise ConnectionError("Not a websocket upgrade request")

        key_line = [line for line in request.decode().split("\r\n") if line.lower().startswith("sec-websocket-key")]
        if not key_line:
            raise ConnectionError("No Sec-WebSocket-Key in request")
        client_key = key_line[0].split(":")[1].strip()

        # Sec-WebSocket-Accept
        accept = base64.b64encode(hashlib.sha1((client_key + self.GUID).encode()).digest()).decode()

        response = (
            "HTTP/1.1 101 Switching Protocols\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Accept: {accept}\r\n"
            "\r\n"
        )
        writer.write(response.encode())
        await writer.drain()

    def unwrap(self, ws_frame: bytes) -> bytes:
        first_byte, second_byte = ws_frame[0], ws_frame[1]
        length = second_byte & 0x7F
        idx = 2

        if length == 126:
            length = struct.unpack("!H", ws_frame[idx:idx + 2])[0]
            idx += 2
        elif length == 127:
            length = struct.unpack("!Q", ws_frame[idx:idx + 8])[0]
            idx += 8

        mask = None
        if second_byte & 0x80:
            mask = ws_frame[idx:idx + 4]
            idx += 4

        payload = ws_frame[idx:idx + length]

        if mask:
            payload = self.mask(payload, mask)

        return payload

    def wrap(self, payload: bytes, mask: bool = False) -> bytes:
        fin_opcode = 0x82  # FIN + binary frame
        length = len(payload)

        if length <= 125:
            header = struct.pack("!BB", fin_opcode, (0x80 if mask else 0) | length)
        elif length < (1 << 16):
            header = struct.pack("!BBH", fin_opcode, (0x80 if mask else 0) | 126, length)
        else:
            header = struct.pack("!BBQ", fin_opcode, (0x80 if mask else 0) | 127, length)

        if mask:
            mask_key = self.rmask
            return header + mask_key + self.mask(payload, mask_key)
        else:
            return header + payload

    @property
    def rmask(self):
        return os.urandom(4)

    def mask(self, data: bytes, mask_key: bytes) -> bytes:
        if not mask_key:
            return data

        masked = bytes(b ^ mask_key[(i + self._mask_offset) % 4] for i, b in enumerate(data))
        self._mask_offset = (self._mask_offset + len(data)) % 4
        return masked

    async def cut_ws_header(self, reader: asyncio.StreamReader) -> tuple[bytes, bytes, bytes]:
        self._mask_offset = 0
        first_two = await reader.readexactly(2)
        first_byte, second_byte = first_two[0], first_two[1]
        length = second_byte & 0x7F
        extended = b""

        if length == 126:
            extended = await reader.readexactly(2)
            length = struct.unpack("!H", extended)[0]
        elif length == 127:
            extended = await reader.readexactly(8)
            length = struct.unpack("!Q", extended)[0]

        mask = b""
        if second_byte & 0x80:
            mask = await reader.readexactly(4)

        return first_two + extended + mask, length, mask