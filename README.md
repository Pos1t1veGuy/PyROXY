# 🔐 Async SOCKS5 Proxy with Custom Encryption

A **SOCKS5 proxy** written in **Python (asyncio)** with pluggable encryption support.
Designed for **customizable handshake obfuscation** and **traffic encryption**.

---

## ✅ Features

* Full **SOCKS5 support** (CONNECT implemented, BIND & UDP ASSOCIATE planned)
* **Async** server and client (`asyncio`)
* **Custom encryption API**:
  * Built-in: `AESCipherCBC`, `AESCipherCRT` (You need to install requirements.txt in 'ext' folder)
  * Default: `Cipher` (no encryption)
* Flexible: Override **handshake stages** or **encrypt/decrypt methods**

---

## 📦 Installation

```bash
git clone https://github.com/Pos1t1veGuy/my_proxy.git
cd my_proxy/ext
pip install -r requirements.txt
```

---

## 🚀 Quick Start

### Start Server

```python
import hashlib
from my_proxy import Socks5Server
from my_proxy.ext.ciphers import AESCipherCTR

key = hashlib.sha256(b'my master key').digest()
SERVER = Socks5Server(users={
    "u1": "pw1",
}, cipher=AESCipherCTR(key=key))
SERVER.start()
```

### Connect Client

```python
import os
import hashlib
from my_proxy import Socks5Client
from my_proxy.ext.basic_ciphers import AESCipherCTR

key = hashlib.sha256(b'my master key').digest()[:16]
iv = os.urandom(16)

client = Socks5Client(cipher=AESCipherCTR(key=key, iv=iv))
client.connect('ifconfig.me', 80, username='u1', password='pw1')
client.send(b"GET / HTTP/1.1\r\nHost: ifconfig.me\r\n\r\n")
print(client.read(-1))
client.close()
```

---

### 📖 Client read methods

```python
    async def aread(self, num_bytes: int = -1, decrypt: bool = True, log_bytes: bool = True, **kwargs) -> bytes:
        # "num_bytes == -1" - means that aread will return every byte before the connection is closed
        ...
    def read(self, num_bytes: int = -1, **kwargs) -> bytes:
        ...
    async def areadexactly(self, num_bytes: int, decrypt: bool = True, log_bytes: bool = True, **kwargs) -> bytes:
        ...
    def readexactly(self, num_bytes: int, **kwargs) -> bytes:
        ...
    async def areaduntil(self, sep: Union[str, bytes] = '\n', decrypt: bool = True, log_bytes: bool = True,
                         bytes_block: int = 1024, limit: int = 65535, **kwargs) -> bytes:
        ...
    def readuntil(self, **kwargs) -> bytes:
        ...
    async def areadline(self, log_bytes: bool = True, decrypt: bool = True, **kwargs) -> bytes:
        ...
    def readline(self, **kwargs) -> bytes:
        ...
```
Here is async `a...` methods and sync. `**kwargs` is passed as an argument to the decryption function.
Important note: block ciphers do not work well with tcp and the client must split the blocks itself.

---

## 🔌 Custom Cipher & Handshake Override

The core of this proxy is the **`Cipher`** class, which defines all stages of the SOCKS5 handshake **and** the methods for traffic encryption/decryption.

You can:

* Override **handshake stages** to change how the proxy negotiates methods, authenticates, or sends commands.
* Implement **custom traffic obfuscation** for data after the handshake.
* Create advanced logic like **fake handshake sequences**, **session keys**, or mimic other protocols for DPI evasion.

---

### 🤝 Handshake structure

To establish a SOCKS5 connection, both the client and server must follow a specific handshake protocol,
which typically consists of 4–5 stages. This class defines symmetric methods for both parties.

---
.[ CLIENT SIDE ] and [ SERVER SIDE ].
---
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
---

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

---

### ✅ Default Cipher (no encryption)

```python
class Cipher:
    @staticmethod
    async def client_send_methods(socks_version: int, methods: List[int]) -> bytes:
        return bytes([socks_version, len(methods), *methods])

    @staticmethod
    async def server_get_methods(socks_version: int, reader: asyncio.StreamReader) -> Dict[str, bool]:
        version, nmethods = await reader.readexactly(2)
        if version != socks_version:
            raise ConnectionError("Unsupported SOCKS version")
        methods = await reader.readexactly(nmethods)
        return {
            'supports_no_auth': 0x00 in methods,
            'supports_user_pass': 0x02 in methods
        }

    # ... (Other handshake steps: method selection, auth, commands)
    
    @staticmethod
    async def encrypt(data: bytes) -> bytes:  # No encryption
        return data

    @staticmethod
    async def decrypt(data: bytes) -> bytes:  # No decryption
        return data
```

---

### 🔐 Create Your Own Cipher

You can **override any stage** of the handshake, for example:

```python
from proxy.cipher import Cipher

class MyCipher(Cipher):
    @staticmethod
    async def client_send_methods(socks_version: int, methods: List[int]) -> bytes:
        # Add obfuscation: reverse order and XOR every byte
        base = await Cipher.client_send_methods(socks_version, methods)
        return bytes(b ^ 0xAA for b in base[::-1])

    @staticmethod
    async def encrypt(data: bytes) -> bytes:
        return data[::-1]  # Reverse data (simple obfuscation)

    @staticmethod
    async def decrypt(data: bytes) -> bytes:
        return data[::-1]
```

Attach it to your server and client:

```python
server = Socks5Server(cipher=MyCipher)
client = Socks5Client(cipher=MyCipher)
```

---

## ✅ Status

* [x] SOCKS5 CONNECT
* [ ] UDP ASSOCIATE (in progress)
* [ ] BIND (planned)

---

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.