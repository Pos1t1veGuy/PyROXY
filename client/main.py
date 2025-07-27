import json
import hashlib
import logging
import os
from pathlib import Path
from logging.handlers import TimedRotatingFileHandler

from ..proxy_client import Socks5Client, Socks5_TCP_Retranslator
from ..ext.wrap_ciphers import *


config_file = Path(__file__).parent / "config.json"
key = b'keykey'
log_file = Path(__file__).parent / 'logs' / "client.log"


os.makedirs(log_file.parent, exist_ok=True)
os.makedirs(config_file.parent, exist_ok=True)

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
config = json.load(open(config_file, 'r', encoding='utf-8'))


CLIENT = Socks5_TCP_Retranslator(
    config['remote_proxy_host'], int(config['remote_proxy_port']),
    cipher=AESCipherCTR_HTTPWS(key=hashlib.sha256(key).digest(), iv=os.urandom(16)),
    udp_cipher=AESCipherCTR(key=hashlib.sha256(key).digest()),
    username=config['username'],
    password=config['password'],
)
CLIENT.logger.addHandler(file_handler)
CLIENT.listen_and_forward(local_host=config['local_proxy_host'], local_port=int(config['local_proxy_port']))