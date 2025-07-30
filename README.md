# 🔐 PyROXY: SOCKS5 Proxy with Custom Encryption

There is a client and a server with interfaces for working in code and for retransmitting system traffic through proxy
clients (like Proxifier).

---

### 🔑 Encryption
The client and server create a tunnel for which you can configure **YOUR CUSTOM ENCRYPTION** and you can rewrite and
edit classes descendants of `Cipher`, to make custom handshake or tunnel encryption.
I made **AES CTR**, **AES CBC** and **ChaCha20-Poly1305** ciphers.

### 🍬 Wrapping
Using `Wrapper` server can obfuscate a trafic. **HTTP_WS_Wrapper makes the proxy indistinguishable from a regular HTTP web server.**
GET to server makes correct response page with `index.html`. So you can even see proxy HTTP wrapper using browser. 

---

## 📦 Installation
```commandline
git clone https://github.com/Pos1t1veGuy/PyROXY.git
```
By default proxy have not requirements, but modules have. `requirements.txt` is in a modules folders (ciphers, wrappers),
you may install it by:
```commandline
pip install -r ./module_name/requirements.txt
```
Or simply:
```commandline
python install_packages.py
```
To install every requirement of all modules

---

## 🚀 Quick Start
For example here is client-server tunnel with AES CTR cipher and HTTP_WS wrapper (to hide into web site)
### Server:
```python
import hashlib
from pyroxy import Socks5Server
from pyroxy.ciphers import AES_CTR
from pyroxy.wrappers import HTTP_WS_Wrapper

key = hashlib.sha256(b'my master key').digest()
SERVER = Socks5Server(users={
    "u1": "pw1",
}, cipher=AES_CTR(key=key, wrapper=HTTP_WS_Wrapper()))
asyncio.run(SERVER.start())
```

### CONNECT EXAMPLE (connect to any server throw proxy)
Client:
```python
import os
import hashlib
from pyroxy import Socks5Client
from pyroxy.ciphers import AES_CTR
from pyroxy.wrappers import HTTP_WS_Wrapper

async def main():
    key = hashlib.sha256(b'my master key').digest()[:16]
    iv = os.urandom(16)

    async with Socks5Client(cipher=AES_CTR(key=key, iv=iv, wrapper=HTTP_WS_Wrapper())) as client:
        session = await client.connect('ifconfig.me', 80, username='u1', password='pw1')
        await session.asend(b"GET / HTTP/1.1\r\nHost: ifconfig.me\r\n\r\n")
        print(await session.aread(-1))

if __name__ == '__main__':
    asyncio.run(main())
```

### UDP ASSOCIATE EXAMPLE (opens UDP server)
```python
async def main():
    key = hashlib.sha256(b'my master key').digest()[:16]
    iv = os.urandom(16)
    client_cipher = AES_CTR(key=key, iv=iv, wrapper=HTTP_WS_Wrapper())
    udp_cipher = AES_CTR(key=key, iv=iv)
    
    async with Socks5Client(cipher=client_cipher, udp_cipher=udp_cipher) as client:
        udp_session, tcp_session = await client.udp_associate(
            '', 0, proxy_host=host, proxy_port=port, username='u1', password='pw1'
        )
    
        transaction_id = 0x1234
        flags = 0x0100
        questions = 1
        answer_rrs = 0
        authority_rrs = 0
        additional_rrs = 0
    
        header = struct.pack("!HHHHHH", transaction_id, flags, questions, answer_rrs, authority_rrs, additional_rrs)
    
        # example.com
        qname = b''.join(
            len(part).to_bytes(1, 'big') + part.encode() for part in "example.com".split('.')
        ) + b'\x00'
        qtype = 1  # A
        qclass = 1  # IN
        question = qname + struct.pack("!HH", qtype, qclass)
    
        dns_query = header + question
    
        udp_session.send(dns_query)
        print(f"Sent UDP packet to {udp_session.host}:{udp_session.port}")
        await asyncio.sleep(.01)
    
        data, addr = await udp_session.recv()
        print(f"Received: {data!r} от {addr}")

if __name__ == '__main__':
    asyncio.run(main())

```

---

## 🧩 Make your cipher

The core of this proxy is the `Cipher` class, which defines all stages of the SOCKS5 handshake and the methods for traffic encryption/decryption.

You can override **handshake stages** to change how the proxy negotiates methods, authenticates, or sends commands.

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

---

## 🍬 Wrapper

Encrypted `Cipher` traffic can be obfuscated using a `Wrapper`.
The `Wrapper` creates `client_hello` and `server_hello` methods to initialize the handshake, and can also obfuscate an
encrypted stream using `wrap` or `unwrap` methods.

1. `wrap`/`unwrap` take encrypted bytes and return obfuscated **bytes**;
2. `client_hello`/`server_hello` return **bool**: True if the greeting was successful;

### Basic Wrapper

```python
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
```

---

## ✏️ User SOCKS5 Commands May Be Overrided!

```python
USER_COMMANDS = {
    0x01: ConnectionMethods.tcp_connection,
    0x02: ConnectionMethods.bind_socket,
    0x03: ConnectionMethods.udp_connection,
}
```
You can add items to my_proxy.USER_COMMANDS dict to SOCKS5 customization

---

## ✅ Status

* [x] SOCKS5 CONNECT
* [x] UDP ASSOCIATE
* [ ] BIND

---

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.