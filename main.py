import json
import os
import logging
import argparse
from pathlib import Path
from logging.handlers import TimedRotatingFileHandler

from pyroxy.proxy_server import Socks5Server
from pyroxy.ciphers import *
from pyroxy.db_handlers import SQLite_Handler
from pyroxy.wrappers import HTTP_WS_Wrapper


parser = argparse.ArgumentParser(description="PyROXY server starter")
logging_levels = ['info', 'debug', 'warning', 'error']
logging_levels += [level.upper() for level in logging_levels]
parser.add_argument("--logging", choices=logging_levels, default='info', help="logging level")
parser.add_argument("--hosting", type=int, choices=[1,0], default=1, help="hosting mode")
args = parser.parse_args()


if args.hosting:
    db_file = Path(__file__).parent / 'pyroxy' / "telegram_bot" / "db.sqlite3"
    key_file = Path(__file__).parent / 'pyroxy' / "telegram_bot" / "default_server_key"
else:
    db_file = Path(__file__).parent / "telegram_bot" / "db.sqlite3"
    key_file = Path(__file__).parent / "telegram_bot" / "default_server_key"
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
    port=80
)

SERVER.logger.setLevel(getattr(logging, args.logging.upper(), logging.INFO))

SERVER.logger.addHandler(file_handler)
asyncio.run(SERVER.start())