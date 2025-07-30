import asyncio


'''
Encrypted CIPHER`s traffic can be obfuscated using a wrapper.
The wrapper creates 'client_hello' and 'server_hello' methods to initialize the handshake, and can also obfuscate an
encrypted stream using 'wrap'/'unwrap' methods.

1. 'wrap'/'unwrap' take encrypted bytes and return obfuscated bytes;
2. 'client_hello'/'server_hello' return bool: True if the greeting was successful;
'''


class Wrapper:
    def __init__(self):
        ...

    async def client_hello(self, client: 'Socks5Client', reader: asyncio.StreamReader,
                           writer: asyncio.StreamWriter) -> bool:
        return True

    async def server_hello(self, server: 'Socks5Server', reader: asyncio.StreamReader,
                           writer: asyncio.StreamWriter) -> bool:
        return True

    def wrap(self, data: bytes) -> bytes:
        return data
    def unwrap(self, data: bytes) -> bytes:
        return data