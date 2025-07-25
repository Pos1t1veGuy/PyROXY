from typing import *
import socket
import struct
import asyncio
import ipaddress as ipa


'''
SOCKS5 HANDSHAKE STRUCTURE (client and server):

To establish a SOCKS5 connection, both the client and server must follow a specific handshake protocol,
which typically consists of 4–5 stages. This class defines symmetric methods for both parties.

▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬
[ CLIENT SIDE ]                         [ SERVER SIDE ]
▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬
0. client_send_methods →              → server_get_methods
   - *If you want it will custom start of your handshake. By default it is empty.
   
1. client_send_methods →              → server_get_methods
   - Client sends SOCKS version and list of supported auth methods.

2. client_get_method ←                ← server_send_method_to_user
   - Server selects an auth method and responds.

3. client_auth_userpass →             → server_auth_userpass
   - If selected method is username/password (0x02), client authenticates.

4. client_command →                   → server_handle_command
   - Client requests to CONNECT, BIND or ASSOCIATE (usually 0x01 = TCP connect),
     and provides destination address and port.

5. client_connect_confirm ←           ← server_make_reply
   - Server replies with success or failure and bound address/port.

▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬

If the handshake is successful (reply code 0x00), the SOCKS tunnel is established.
All further traffic is sent over this tunnel.

After that:
- `encrypt(data)` and `decrypt(data)` are used to optionally obfuscate or secure traffic.
- These can be customized (e.g., with XOR, AES, session keys, etc.) to implement encryption
  or detection evasion mechanisms similar to obfs4 or ShadowSocks.

Each `Cipher` subclass must implement or override:
- Handshake stages (client and/or server side)
- `encrypt(data: bytes) -> bytes`
- `decrypt(data: bytes) -> bytes`
'''


class Cipher:
    def __init__(self, *args, **kwargs):
        self.is_client = False
        self.is_server = False
        self._init_args = args
        self._init_kwargs = kwargs

    def copy(self) -> 'Cipher':
        return self.__class__(*self._init_args, **self._init_kwargs)

    @staticmethod
    async def server_hello(server: 'Socks5Server', user: 'User', reader: asyncio.StreamReader,
                                   writer: asyncio.StreamWriter) -> bool:
        ...

    @staticmethod
    async def client_hello(client: 'Socks5Client', reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> bool:
        ...

    @staticmethod
    async def client_send_methods(socks_version: int, methods: List[int]) -> bytes:
        return bytes([
            socks_version,
            len(methods),
            *methods,
        ])

    @staticmethod
    async def server_get_methods(socks_version: int, reader: asyncio.StreamReader) -> Dict[str, bool]:
        version, nmethods = await reader.readexactly(2)
        if version != socks_version:
            raise ConnectionError(f"Unsupported SOCKS version: {version}")

        methods = await reader.readexactly(nmethods)

        return {
            'supports_no_auth': 0x00 in methods,
            'supports_user_pass': 0x02 in methods
        }

    @staticmethod
    async def server_send_method_to_user(socks_version: int, method: int) -> bytes:
        return bytes([socks_version, method])

    @staticmethod
    async def client_get_method(socks_version: int, reader: asyncio.StreamReader) -> int:
        response = await reader.readexactly(2)

        if response[0] != socks_version:
            raise ConnectionError(f"Unsupported SOCKS version: {version}")
        if response[1] == 0xFF:
            raise ConnectionError("No acceptable authentication methods.")

        return response[1]

    @staticmethod
    async def server_auth_userpass(logins: Dict[str, str], reader: asyncio.StreamReader,
                            writer: asyncio.StreamWriter) -> Optional[Tuple[str, str]]:
        auth_version = (await reader.readexactly(1))[0]

        if auth_version == 1:
            username_length = (await reader.readexactly(1))[0]
            username = (await reader.readexactly(username_length)).decode()

            pw_length = (await reader.readexactly(1))[0]
            pw = (await reader.readexactly(pw_length)).decode()

            if logins.get(username) == pw:
                writer.write(bytes([1, 0]))
                await writer.drain()
                return username, pw
            else:
                writer.write(bytes([1, 1]))
                await writer.drain()

    @staticmethod
    async def client_auth_userpass(username: str, password: str, reader: asyncio.StreamReader,
                                   writer: asyncio.StreamWriter) -> bool:
        username_bytes = username.encode()
        password_bytes = password.encode()

        data = bytes([0x01, len(username_bytes)]) + username_bytes + bytes([len(password_bytes)]) + password_bytes
        writer.write(data)
        await writer.drain()

        resp = await reader.readexactly(2)
        try:
            return resp[1] == 0x00
        except IndexError:
            raise ConnectionError(f'Invalid answer received {resp}')

    @staticmethod
    async def client_command(socks_version: int, user_command: int, target_host: str, target_port: int) -> bytes:
        try:
            ip = ipa.ip_address(target_host)
            if ip.version == 4: # IPv4
                atyp = 0x01
                addr_part = ip.packed
            else: # IPv6
                atyp = 0x04
                addr_part = ip.packed
        except ValueError: # domain
            atyp = 0x03
            addr_bytes = target_host.encode("idna")
            if len(addr_bytes) > 255:
                raise ValueError("Domain name too long for SOCKS5")
            addr_part = struct.pack("!B", len(addr_bytes)) + addr_bytes

        request = struct.pack("!BBB", socks_version, user_command, 0x00)
        request += struct.pack("!B", atyp) + addr_part + struct.pack("!H", target_port)
        return request

    @staticmethod
    async def server_handle_command(socks_version: int, user_command_handlers: Dict[int, Callable],
                             reader: asyncio.StreamReader) -> Tuple[str, int, Callable]:

        version, cmd, rsv, address_type = await reader.readexactly(4)
        if version != socks_version:
            raise ConnectionError(f"Unsupported SOCKS version: {version}")

        if not cmd in user_command_handlers.keys():
            raise ConnectionError(f"Unsupported command: {cmd}, it must be one of {list(user_command_handlers.keys())}")
        cmd = user_command_handlers[cmd]

        match address_type:
            case 0x01: # IPv4
                addr_bytes = await reader.readexactly(4)
                addr = '.'.join(map(str, addr_bytes))
            case 0x03: # domain
                domain_length = (await reader.readexactly(1))[0]
                domain_bytes = await reader.readexactly(domain_length)
                addr = domain_bytes.decode()
            case 0x04: # IPv6
                addr_bytes = await reader.readexactly(16)
                addr = socket.inet_ntop(socket.AF_INET6, addr_bytes)
            case _:
                raise ConnectionError(f"Invalid address: {address_type}, it must be 0x01/0x03/0x04")

        port_bytes = await reader.readexactly(2)
        port = int.from_bytes(port_bytes, byteorder='big')
        return addr, port, cmd

    @staticmethod
    async def server_make_reply(socks_version: int, reply_code: int, address: str = '0', port: int = 0) -> bytes:
        address_type = 0x01
        head = "!BBBB"
        addr_data = socket.inet_aton("0.0.0.0")
        tail = "4sH"

        try:
            ip = ipa.ip_address(address)

            if ip.version == 4:
                addr_data = ip.packed

            elif ip.version == 6:
                address_type = 0x04
                addr_data = ip.packed
                tail = "16sH"

        except ValueError:
            addr_bytes = address.encode('idna')
            if len(addr_bytes) > 255:
                raise ValueError("Domain name too long for SOCKS5 protocol")

            address_type = 0x03
            addr_data = bytes([len(addr_bytes)]) + addr_bytes
            tail = f"{1 + len(addr_bytes)}sH"

        except:
            address_type = 0x01
            port = 0

        return struct.pack(
            head + tail,
            socks_version,
            reply_code,
            0x00,  # RSV
            address_type,
            addr_data,
            port
        )

    @staticmethod
    async def client_connect_confirm(reader: asyncio.StreamReader) -> Tuple[str, str]:
        hdr = await reader.readexactly(4)
        ver, rep, rsv, atyp = hdr

        if ver != 0x05:
            raise ConnectionError(f"Invalid SOCKS version in reply: {ver}")
        if rep != 0x00:
            raise ConnectionError(f"SOCKS5 request failed, REP={rep}")

        if atyp == 0x01:  # IPv4
            addr_bytes = await reader.readexactly(4)
            port_bytes = await reader.readexactly(2)
            address = socket.inet_ntoa(addr_bytes)

        elif atyp == 0x03:  # Domain
            domain_len = await reader.readexactly(1)[0]
            addr_bytes = await reader.readexactly(domain_len)
            port_bytes = await reader.readexactly(2)
            address = addr_bytes.decode('idna')

        elif atyp == 0x04:  # IPv6
            addr_bytes = await reader.readexactly(16)
            port_bytes = await reader.readexactly(2)
            address = socket.inet_ntop(socket.AF_INET6, addr_bytes)

        else:
            raise ConnectionError(f"Invalid ATYP in reply: {atyp}")

        return address, struct.unpack('!H', port_bytes)[0]


    @staticmethod
    def encrypt(data: bytes) -> bytes:
        return data

    @staticmethod
    def decrypt(data: bytes) -> bytes:
        return data


class IVCipher(Cipher):
    def __init__(self, key: bytes, iv: Optional[bytes] = None):
        super().__init__(key, iv=iv)
        self.key = key
        assert iv is None or len(iv) == 16, "IV must be exactly 16 bytes"
        self.iv = iv
        self.encryptor = None
        self.decryptor = None

        if iv is not None:
            self._init_ciphers(iv)

    def _init_ciphers(self, iv: bytes):
        raise NotImplementedError("Override this method in subclass")