from typing import *
import asyncio

from cipher import Cipher
from logger_setup import logger


class Socks5Client:
    def __init__(self, cipher: Optional[Cipher] = None):
        self.socks_version = 5
        self.cipher = Cipher if cipher is None else cipher
        self.reader: Optional[asyncio.StreamReader] = None
        self.writer: Optional[asyncio.StreamWriter] = None

        self.user_commands = {
            'connect': 0x01,
            'bind': 0x03,
            'associate': 0x04,
        }
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)

    async def async_connect(self, target_host: str, target_port: int,
                            host: str = '127.0.0.1', port: int = 1080,
                            username: Optional[str] = None, password: Optional[str] = None):

        self.reader, self.writer = await asyncio.open_connection(host, port)
        logger.info(f"Connected to SOCKS5 proxy at {host}:{port}")

        methods = [0x00]
        if username and password:
            methods.insert(0, 0x02)

        await self.asend(await self.cipher.client_greetings([
            self.socks_version,
            len(methods),
            *methods,
        ]))
        method_chosen = await self.cipher.client_greetings_response(self.reader)

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
        await self.asend(cmd_bytes)
        await self.cipher.client_connect_confirm(self.reader)

        logger.info(f"Connected to {target_host}:{target_port} through proxy.")

    def connect(self, target_host: str, target_port: int,
                host: str = '127.0.0.1', port: int = 1080,
                username: Optional[str] = None, password: Optional[str] = None):
        return self._loop.run_until_complete(
            self.async_connect(target_host, target_port, host=host, port=port, username=username, password=password)
        )

    async def asend(self, data: bytes):
        self.writer.write(await self.cipher.encrypt(data))
        await self.writer.drain()

    def send(self, data: bytes):
        return self._loop.run_until_complete(self.asend(data))

    async def arecv(self, num_bytes: int) -> bytes:
        encrypted = await self.reader.readexactly(num_bytes)
        return await self.cipher.decrypt(encrypted)

    def recv(self, num_bytes: int):
        return self._loop.run_until_complete(self.arecv(num_bytes))

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
    # from ext.basic_ciphers import AESCipher

    # key = hashlib.sha256(b'my master key').digest()[:16]
    # iv = os.urandom(16)

    client = Socks5Client()#cipher=AESCipher(key, iv))
    client.connect('ifconfig.me', 80, username='u1', password='pw1')
    client.send(b"GET / HTTP/1.1\r\nHost: ifconfig.me\r\n\r\n")
    print(client.recv(512))
    client.close()