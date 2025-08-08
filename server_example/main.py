import json
import os
import logging
from pathlib import Path
from logging.handlers import TimedRotatingFileHandler

from ..proxy_server import Socks5Server
from ..ciphers import *
from ..db_handlers import SQLite_Handler
from ..wrappers import HTTP_WS_Wrapper


db_file = Path(__file__).parent.parent / "telegram_bot" / "db.sqlite3"
key_file = Path(__file__).parent.parent / "telegram_bot" / "default_server_key"
log_file = Path(__file__).parent / 'logs' / "proxy.log"


os.makedirs(log_file.parent, exist_ok=True)
os.makedirs(db_file.parent, exist_ok=True)

file_handler = TimedRotatingFileHandler(
    log_file,
    when="midnight",
    interval=1,
    backupCount=30,
    encoding="utf-8"
)
formatter = logging.Formatter(
    fmt="[{asctime}] [{levelname}] {message}",
    datefmt="%Y-%m-%d %H:%M:%S",
    style="{"
)
file_handler.setFormatter(formatter)
key = bytes.fromhex(open(key_file, 'r').read())

available_ciphers = [
    Cipher(wrapper=HTTP_WS_Wrapper()), # starts a handshake with client_hello and server_hello from wrapper
    AES_CBC(key=key, iv=os.urandom(16)),
    AES_CTR(key=key, iv=os.urandom(16)),
    ChaCha20_Poly1305(key=key),
]
SERVER = Socks5Server(
    db_handler=SQLite_Handler(filepath=db_file),
    ciphers=available_ciphers,
    udp_cipher=available_ciphers[2],
    port=180
)
# SERVER.logger.addHandler(file_handler)
asyncio.run(SERVER.start())