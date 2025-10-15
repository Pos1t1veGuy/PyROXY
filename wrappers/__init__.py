from typing import *
import asyncio
import base64
import hashlib
import os
import traceback
import logging
import requests
import ipaddress
from pathlib import Path
from fake_useragent import UserAgent

from ..base_wrapper import Wrapper


class HTTP_WS_Wrapper(Wrapper):
    GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

    def __init__(self, server_ip: str = '127.0.0.1', http_path: str = "/", ws_path: str = "/ws/",
                 host: str = 'example.com', icon_path: Optional[str] = None, http_response_file: Optional[str] = None,
                 timeout: int = 5, ws_timeout: int = 60):
        self.http_path = http_path
        self.ws_path = ws_path[:-1] if ws_path.endswith('/') else ws_path
        self.ip = server_ip
        self.host = host
        self.use_ssl = host == 'example.com'
        self.timeout = timeout
        self.ws_timeout = ws_timeout
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

        self._mask_offset = 0
        self.connection_alive = False
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
        self.ERROR505 = b'''HTTP/1.1 505 HTTP Version Not Supported
Content-Type: text/html; charset=UTF-8
Content-Length: 171
Connection: close

<html>
<head><title>505 HTTP Version Not Supported</title></head>
<body>
<center><h1>505 HTTP Version Not Supported</h1></center>
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

    async def http_client_hello(self, client: 'Socks5Client', reader: asyncio.StreamReader,
                                writer: asyncio.StreamWriter) -> bool:
        headers = {
            "User-Agent": self.client_user_agent,
            "Accept": "text/html",
            "Connection": "close",
        }

        try:
            response = requests.get(
                f"http{'s' if self.use_ssl else ''}://{self.host if self.use_ssl else self.ip}{self.http_path}",
                headers=headers,
                timeout=self.timeout,
                verify=self.use_ssl
            )
            return response.status_code == 200
        except requests.RequestException as e:
            raise ConnectionError(f"HTTP handshake failed: {e}")

    async def http_server_hello(self, server: 'Socks5Server', reader: asyncio.StreamReader,
                                writer: asyncio.StreamWriter, request_str: str) -> bool:
        method, path, version = request_str.split()[:3]

        headers = {}
        for line in request_str.split('\r\n'):
            if not line:
                continue
            if ':' not in line:
                continue
            name, val = line.split(':', 1)
            headers[name.strip().lower()] = val.strip()

        conn_hdr = headers.get('connection')
        proxy_conn_hdr = headers.get('proxy-connection')
        effective_conn = conn_hdr if conn_hdr is not None else proxy_conn_hdr

        tokens = []
        if effective_conn:
            tokens = [t.strip().lower() for t in effective_conn.split(',') if t.strip()]

        keep_alive = 'keep-alive' in tokens
        ver = version.strip().upper()
        if ver.startswith('HTTP/1.1'):
            if 'close' not in tokens:
                keep_alive = True
        elif ver.startswith('HTTP/1.0'):
            if 'keep-alive' in tokens:
                keep_alive = True
        else:
            return await self.http_error(505, writer)

        self.connection_alive = keep_alive

        response_format = (
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/html; charset=utf-8\r\n"
            "Content-Length: {}\r\n"
            f"Connection: {'keep-alive' if keep_alive else 'close'}\r\n"
            "\r\n"
        )

        if not 'host' in request_str.lower():
            await asyncio.sleep(self.timeout)
            return await self.http_error(408, writer)

        if method.upper() == 'GET':
            if path == '/' + self.icon_path.name:
                icon_data = self.favicon_response
                return await self.http_response(
                    response_format.format(str(len(icon_data))).encode() + icon_data, writer
                )
            elif path == self.http_path:
                content = self.index_html_response
                return await self.http_response(response_format.format(str(len(content))).encode() + content, writer)
            else:
                return await self.http_error(404, writer)

        elif method.upper() == 'HEAD':
            if path == '/' + self.icon_path.name:
                return await self.http_response(
                    response_format.format(str(len(self.favicon_response))).encode(), writer
                )
            elif path == self.http_path:
                return await self.http_response(
                    response_format.format(str(len(self.index_html_response))).encode(), writer
                )
            else:
                return await self.http_error(404, writer)

        else:
            return await self.http_error(405, writer)

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
                           writer: asyncio.StreamWriter, request_str: str) -> bool:
        method, path, version = request_str.split()[:3]
        key_line = [line for line in request_str.split("\r\n") if line.lower().startswith("sec-websocket-key")]

        if "upgrade: websocket" not in request_str.lower():
            return await self.http_error(404, writer)
        elif method != "GET":
            return await self.http_error(405, writer)
        elif path != self.ws_path or (path.endswith('/') and path[:-1] != self.ws_path):
            return await self.http_error(404, writer)
        elif not 'Host:' in request_str:
            await asyncio.sleep(self.timeout)
            return await self.http_error(408, writer)
        elif not key_line:
            return await self.http_error(404, writer)

        client_key = key_line[0].split(":")[1].strip()
        accept = base64.b64encode(hashlib.sha1((client_key + self.GUID).encode()).digest()).decode()
        self.connection_alive = True
        return await self.http_response((
            "HTTP/1.1 101 Switching Protocols\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Accept: {accept}\r\n"
            "\r\n"
        ).encode(), writer)

    async def client_hello(self, client: 'Socks5Client', reader: asyncio.StreamReader,
                           writer: asyncio.StreamWriter) -> bool:
        http_result = await self.http_client_hello(client, reader, writer)
        ws_result = await self.ws_client_hello(client, reader, writer)
        return http_result and ws_result

    async def server_hello(self, server: 'Socks5Server', user: 'User', reader: asyncio.StreamReader,
                           writer: asyncio.StreamWriter) -> bool:
        try:
            try:
                request = await reader.readuntil(b"\r\n\r\n")
            except asyncio.IncompleteReadError:
                return await self.http_error(400, writer)

            request_str = request.decode(errors='ignore')

            if "Connection: Upgrade" in request_str or 'Upgrade: websocket' in request_str:
                return await self.ws_server_hello(server, reader, writer, request_str)
            else:
                return await self.http_server_hello(server, reader, writer, request_str)
        except Exception as ex:
            if server.logger.isEnabledFor(logging.DEBUG):
                traceback.print_exc()
            server.logger.error(f'Server hello error: {ex}')
            return await self.http_error(500, writer)


    async def handle_suspicious_client(self, server: 'Socks5Server', user: 'User', reader: asyncio.StreamReader,
                                       writer: asyncio.StreamWriter):
        if self.connection_alive:
            await asyncio.sleep(self.ws_timeout) # and then disconnect


    @property
    def index_html_response(self) -> bytes:
        with open(self.http_file_path, 'r', encoding='utf-8') as f:
            return f.read().strip().encode()
    @property
    def favicon_response(self) -> bytes:
        with open(self.icon_path, 'rb') as f:
            return f.read()

    async def http_error(self, num: int, writer: asyncio.StreamWriter) -> bool:
        try:
            writer.write(self.errors[num])
            await writer.drain()
            return False
        except ConnectionResetError:
            pass

    async def http_response(self, content: bytes, writer: asyncio.StreamWriter) -> bool:
        writer.write(content)
        await writer.drain()
        return True


class ProxyProtocolWrapper(Wrapper):
    async def server_hello(self, server: 'Socks5Server', user: 'User', reader: asyncio.StreamReader,
                           writer: asyncio.StreamWriter) -> bool:
        try:
            proxy_data = (await reader.readuntil(b"\r\n"))[:-2].decode(errors='ignore').split(' ')
            if proxy_data[0] != 'PROXY':
                return False

            _, _, client_addr, server_addr, client_port, server_port = proxy_data
            user.ip, user.port = client_addr, client_port
            return True
        except Exception as ex:
            if server.logger.isEnabledFor(logging.DEBUG):
                traceback.print_exc()
            server.logger.error(f'Server hello error: {ex}')
            return False


class PP_HTTP_WS_Wrapper(HTTP_WS_Wrapper):
    async def server_hello(self, server: 'Socks5Server', user: 'User', reader: asyncio.StreamReader,
                           writer: asyncio.StreamWriter) -> bool:
        pproc_hello = await ProxyProtocolWrapper.server_hello(self, server, user, reader, writer)
        http_ws_hello = await super().server_hello(server, user, reader, writer)
        return pproc_hello and http_ws_hello