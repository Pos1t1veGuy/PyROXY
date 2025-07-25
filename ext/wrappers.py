from typing import *
import asyncio
import base64
import struct
import hashlib
import os
from fake_useragent import UserAgent


class Wrapper: ...

class HTTP_WS_Wrapper(Wrapper):
    GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

    def __init__(self, http_path: str = "/", ws_path: str = "/ws/", host: str = "example.com",
                 http_response_file: Optional[str] = None, timeout: int = 5):
        self.http_path = http_path
        self.ws_path = ws_path
        self.host = host
        self.timeout = timeout
        self.client_user_agent = user_agent = UserAgent().random

        if http_response_file is None:
            http_response_file = os.path.dirname(__file__) + '/index.html'
        if not os.path.isfile(http_response_file):
            raise FileNotFoundError(f"HTTP response file '{http_response_file}' not found")
        self.http_file_path = http_response_file
        with open(http_response_file, 'r', encoding='utf-8') as f:
            self.http_response = f.read().strip()
        self.http_content_length = len(self.http_response.encode())

        self._mask_offset = 0
        self.ERROR400 = b'''HTTP/1.1 400 Bad Request
Content-Type: text/html; charset=UTF-8
Content-Length: 155
Connection: close

<html>
<head><title>400 Bad Request</title></head>
<body>
<center><h1>400 Bad Request</h1></center>
<hr><center>nginx/1.24.0</center>
</body>
</html>
'''
        self.ERROR403 = b'''HTTP/1.1 403 Forbidden
Content-Type: text/html; charset=UTF-8
Content-Length: 162
Connection: close

<html>
<head><title>403 Forbidden</title></head>
<body>
<center><h1>403 Forbidden</h1></center>
<hr><center>nginx/1.24.0</center>
</body>
</html>
'''
        self.ERROR404 = b'''HTTP/1.1 404 Not Found
Content-Type: text/html; charset=UTF-8
Content-Length: 153
Connection: close

<html>
<head><title>404 Not Found</title></head>
<body>
<center><h1>404 Not Found</h1></center>
<hr><center>nginx/1.24.0</center>
</body>
</html>
'''
        self.ERROR405 = b'''HTTP/1.1 405 Method Not Allowed
Content-Type: text/html; charset=UTF-8
Content-Length: 166
Connection: close
Allow: GET

<html>
<head><title>405 Not Allowed</title></head>
<body>
<center><h1>405 Not Allowed</h1></center>
<hr><center>nginx/1.24.0</center>
</body>
</html>
'''
        self.ERROR408 = b'''HTTP/1.1 408 Request Timeout
Content-Type: text/html; charset=UTF-8
Content-Length: 168
Connection: close

<html>
<head><title>408 Request Timeout</title></head>
<body>
<center><h1>408 Request Timeout</h1></center>
<hr><center>nginx/1.24.0</center>
</body>
</html>
'''
        self.ERROR500 = b'''HTTP/1.1 500 Internal Server Error
Content-Type: text/html; charset=UTF-8
Content-Length: 162
Connection: close

<html>
<head><title>500 Internal Server Error</title></head>
<body>
<center><h1>500 Internal Server Error</h1></center>
<hr><center>nginx/1.24.0</center>
</body>
</html>
'''

        self.errors = {}
        for attr_name in dir(self):
            if attr_name.startswith('ERROR'):
                num = int(attr_name.split('ERROR')[1])
                attr = getattr(self, attr_name)

                if attr[-1] != b'\n':
                    attr += b'\n'
                if attr[-2] != b'\n':
                    attr += b'\n'
                attr = b'\n\r'.join(attr.split(b'\n'))

                setattr(self, attr_name, attr)
                self.errors[num] = attr

    async def http_client_hello(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> bool:
        http_get = (
            f"GET {self.http_path} HTTP/1.1\r\n"
            f"Host: {self.host}\r\n"
            f"User-Agent: {self.client_user_agent}\r\n"
            "Accept: text/html\r\n"
            "Connection: close\r\n"
            "\r\n"
        )
        writer.write(http_get.encode())
        await writer.drain()

        try:
            headers = await reader.readuntil(b"\r\n\r\n")
        except asyncio.IncompleteReadError:
            raise ConnectionError('Server gets invalid response')

        response = headers
        content_length = int(headers.split(b'Content-Length: ')[1].split(b'\r\n')[0])
        response += await reader.readexactly(content_length)

        return b'200 OK' in response

    async def http_server_hello(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> bool:
        try:
            try:
                request = await reader.readuntil(b"\r\n\r\n")
            except asyncio.IncompleteReadError:
                return await self.http_error(writer, 400)

            request_str = request.decode(errors='ignore')
            method, path, version = request_str.split()[:3]

            if method != "GET":
                return await self.http_error(writer, 405)
            if path != self.http_path:
                return await self.http_error(writer, 404)
            if not 'Host:' in request_str:
                await asyncio.sleep(self.timeout)
                return await self.http_error(writer, 408)

            response = (
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: text/html; charset=utf-8\r\n"
                f"Content-Length: {self.http_content_length}\r\n"
                "Cache-Control: no-cache, no-store, must-revalidate\r\n"
                "Pragma: no-cache\r\n"
                "Expires: 0\r\n"
                "Connection: close\r\n"
                "X-Powered-By: PHP/7.4.3\r\n"
                "\r\n"
                f"{self.http_response}"
            )

            writer.write(response.encode())
            await writer.drain()
            return True
        except Exception as ex:
            server.logger.error(f'Server hello error: {ex}')
            return await self.http_error(writer, 500)

    async def ws_client_hello(self, client: 'Socks5Client', reader: asyncio.StreamReader,
                              writer: asyncio.StreamWriter) -> bool:
        key = base64.b64encode(os.urandom(16)).decode()
        http_get = (
            f"GET {self.ws_path} HTTP/1.1\r\n"
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
        return b"101" in response and b"Switching Protocols" in response

    async def ws_server_hello(self, server: 'Socks5Server', reader: asyncio.StreamReader,
                           writer: asyncio.StreamWriter) -> bool:
        try:
            try:
                request = await reader.readuntil(b"\r\n\r\n")
            except asyncio.exceptions.IncompleteReadError:
                await asyncio.sleep(self.timeout)
                return await self.http_error(writer, 408)

            request_str = request.decode(errors='ignore')
            method, path, version = request_str.split()[:3]

            if "upgrade: websocket" not in request_str.lower():
                return await self.http_error(writer, 404)
            if method != "GET":
                return await self.http_error(writer, 405)
            if path != self.ws_path:
                return await self.http_error(writer, 404)
            if not 'Host:' in request_str:
                await asyncio.sleep(self.timeout)
                return await self.http_error(writer, 408)

            key_line = [line for line in request.decode().split("\r\n") if line.lower().startswith("sec-websocket-key")]
            if not key_line:
                return await self.http_error(writer, 404)
            client_key = key_line[0].split(":")[1].strip()
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
            return True
        except Exception as ex:
            server.logger.error(f'Server hello error: {ex}')
            return await self.http_error(writer, 500)

    async def client_hello(self, client: 'Socks5Client', reader: asyncio.StreamReader,
                           writer: asyncio.StreamWriter) -> bool:
        http = await self.http_client_hello(reader, writer)
        ws = await self.ws_client_hello(client, reader, writer)
        return http and ws

    async def server_hello(self, server: 'Socks5Server', reader: asyncio.StreamReader,
                           writer: asyncio.StreamWriter) -> bool:
        http = await self.http_server_hello(reader, writer)
        ws = await self.ws_server_hello(server, reader, writer)
        return http and ws

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

    async def http_error(self, writer, num: int) -> bool:
        writer.write(self.errors[num])
        await writer.drain()
        writer.close()
        return False