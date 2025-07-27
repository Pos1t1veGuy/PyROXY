import json
import hashlib
import os
import logging
from pathlib import Path
from logging.handlers import TimedRotatingFileHandler

from ..proxy_server import Socks5Server
from ..ext.wrap_ciphers import *


users_file = Path(__file__).parent / "users.json"
key = b'keykey'
log_file = Path(__file__).parent / 'logs' / "proxy.log"


os.makedirs(log_file.parent, exist_ok=True)
os.makedirs(users_file.parent, exist_ok=True)

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
users = json.load(open(users_file, 'r', encoding='utf-8'))


SERVER = Socks5Server(
    users=users['users'],
    accept_anonymous=users['accept_anonymous'],
    cipher=AESCipherCTR(key=hashlib.sha256(key).digest()),
    udp_cipher=AESCipherCTR(key=hashlib.sha256(key).digest()),
    port=180,
)
SERVER.logger.addHandler(file_handler)
SERVER.start()