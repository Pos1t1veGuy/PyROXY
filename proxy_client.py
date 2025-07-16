from typing import *
import asyncio

from base_cipher import Cipher
from logger_setup import logger


class Socks5Client:
    def __init__(self, cipher: Optional[Cipher] = None, log_bytes: bool = True):
        self.socks_version = 5
        self.cipher = Cipher if cipher is None else cipher
        self.log_bytes = log_bytes # only after handshake
        self.reader: Optional[asyncio.StreamReader] = None
        self.writer: Optional[asyncio.StreamWriter] = None
        self.bytes_sent = 0
        self.bytes_received = 0

        self.user_commands = {
            'connect': 0x01,
            'bind': 0x03,
            'associate': 0x04,
        }
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)

    async def async_connect(self, target_host: str, target_port: int,
                            proxy_host: str = '127.0.0.1', proxy_port: int = 1080,
                            username: Optional[str] = None, password: Optional[str] = None):

        self.reader, self.writer = await asyncio.open_connection(proxy_host, proxy_port)
        logger.info(f"Connected to SOCKS5 proxy at {proxy_host}:{proxy_port}")

        methods = [0x00]
        if username and password:
            methods.insert(0, 0x02)

        methods_msg = await self.cipher.client_send_methods(self.socks_version, methods)
        await self.asend(methods_msg, encrypt=False, log_bytes=False)
        method_chosen = await self.cipher.client_get_method(self.reader)

        if method_chosen == 0xFF:
            raise ConnectionError("No acceptable authentication methods.")

        if method_chosen == 0x02:
            if not username or not password:
                raise ConnectionError("Proxy requires username/password authentication, but none provided")

            auth_ok = await self.cipher.client_auth_userpass(username, password, self.reader, self.writer)
            if not auth_ok:
                raise ConnectionError("Authentication failed")
            logger.info("Authenticated successfully")

        elif method_chosen == 0x00:
            logger.info("No authentication required by proxy")

        else:
            raise ConnectionError(f"Unsupported authentication method selected by proxy: {method_chosen}")

        cmd_bytes = await self.cipher.client_command(
            self.socks_version, self.user_commands['connect'], target_host, target_port
        )
        await self.asend(cmd_bytes, encrypt=False, log_bytes=False)
        connected = await self.cipher.client_connect_confirm(self.reader)

        if connected:
            logger.info(f"Connected to {target_host}:{target_port} through proxy")
        else:
            logger.error(f'Failed to connect to {target_host}:{target_port} through proxy {host}:{port}')
            await self.close()

    def connect(self, target_host: str, target_port: int,
                proxy_host: str = '127.0.0.1', proxy_port: int = 1080,
                username: Optional[str] = None, password: Optional[str] = None):
        return self._loop.run_until_complete(self.async_connect(target_host, target_port,
                                    proxy_host=proxy_host, proxy_port=proxy_port, username=username, password=password))

    async def asend(self, data: bytes, encrypt: bool = True, log_bytes: bool = True):
        data = await self.cipher.encrypt(data) if encrypt else data
        if self.log_bytes and log_bytes:
            self.bytes_sent += len(data)
        self.writer.write(data)
        await self.writer.drain()

    def send(self, data: bytes, encrypt: bool = True):
        return self._loop.run_until_complete(self.asend(data, encrypt=encrypt))

    async def arecv(self, num_bytes: int, decrypt: bool = True, log_bytes: bool = True, **kwargs) -> bytes:
        data = await self.reader.readexactly(num_bytes)
        if self.log_bytes and log_bytes:
            self.bytes_received += len(data)
        return await self.cipher.decrypt(data, **kwargs) if decrypt else data

    def recv(self, num_bytes: int, **kwargs):
        return self._loop.run_until_complete(self.arecv(num_bytes, **kwargs))

    async def async_close(self):
        if self.writer:
            self.writer.close()
            await self.writer.wait_closed()
            logger.info("Connection closed.")

    def close(self):
        self._loop.run_until_complete(self.async_close())
        self._loop.stop()
        self._loop.close()


if __name__ == '__main__':
    from ext.basic_ciphers import AESCipherCTR

    key = hashlib.sha256(b'my master key').digest()[:16]
    iv = os.urandom(16)

    client = Socks5Client(cipher=AESCipherCTR(key, iv))
    client.connect('ifconfig.me', 80, username='u1', password='pw1')
    client.send(b"GET / HTTP/1.1\r\nHost: ifconfig.me\r\n\r\n")
    print(client.recv(512))
    client.close()