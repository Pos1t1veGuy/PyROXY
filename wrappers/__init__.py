from typing import *
import asyncio
import base64
import hashlib
import os
from pathlib import Path
from fake_useragent import UserAgent

from ..base_wrapper import Wrapper


class HTTP_WS_Wrapper(Wrapper):
    GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

    def __init__(self, http_path: str = "/", ws_path: str = "/ws/", host: str = "example.com",
                 icon_path: Optional[str] = None, http_response_file: Optional[str] = None, timeout: int = 5):
        self.http_path = http_path
        self.ws_path = ws_path
        self.host = host
        self.timeout = timeout
        self.client_user_agent = user_agent = UserAgent().random

        if icon_path is None:
            self.icon_path = Path(__file__).parent / "r0xy.png"
        else:
            self.icon_path = Path(icon_path)

        if http_response_file is None:
            http_response_file = os.path.dirname(__file__) + '/index.html'
        if not os.path.isfile(http_response_file):
            raise FileNotFoundError(f"HTTP response file '{http_response_file}' not found")
        self.http_file_path = http_response_file
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
            if not 'Host:' in request_str:
                await asyncio.sleep(self.timeout)
                return await self.http_error(writer, 408)

            if path == '/' + self.icon_path.name:
                await self.handle_favicon(reader, writer)
            elif path == self.http_path:
                response = (
                    "HTTP/1.1 200 OK\r\n"
                    "Content-Type: text/html; charset=utf-8\r\n"
                    f"Content-Length: {self.http_content_length}\r\n"
                    "Connection: close\r\n"
                    "\r\n"
                    f"{self.http_response}"
                )

                writer.write(response.encode())
                await writer.drain()

                return True
            else:
                return await self.http_error(writer, 404)

        except Exception as ex:
            server.logger.error(f'Server hello error: {ex}')
            return await self.http_error(writer, 500)

    async def handle_favicon(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        with open(self.icon_path, 'rb') as f:
            icon_data = f.read()

        response = (
                b'HTTP/1.1 200 OK\r\n'
                b'Content-Type: image/png\r\n'
                b'Content-Length: ' + str(len(icon_data)).encode() + b'\r\n'
                b'Connection: close\r\n'
                b'\r\n' + icon_data
        )
        writer.write(response)
        await writer.drain()

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

    async def http_error(self, writer, num: int) -> bool:
        try:
            writer.write(self.errors[num])
            await writer.drain()
            writer.close()
            return False
        except ConnectionResetError:
            pass


    @property
    def http_response(self) -> str:
        with open(self.http_file_path, 'r', encoding='utf-8') as f:
            return f.read().strip()