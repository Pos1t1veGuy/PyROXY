import json
import logging
import os
from pathlib import Path
from logging.handlers import TimedRotatingFileHandler

from ..proxy_client import Socks5Client, Socks5_TCP_Retranslator
from ..ciphers import *
from ..wrappers import HTTP_WS_Wrapper


config_file = Path(__file__).parent / "config.json"
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

key = b'\x86P\x0e\xd3\xd4\xf2\xbc\x19\x1f\x98\xc5\xd0e\xf3X\x07\xf7\xd5R_\x9b\x1c\x92R\xe0}JY\x94\x01nF'
available_ciphers = [
    Cipher(wrapper=HTTP_WS_Wrapper()), # starts a handshake with client_hello and server_hello from wrapper
    AES_CBC(key=key, iv=os.urandom(16)),
    AES_CTR(key=key, iv=os.urandom(16)),
    ChaCha20_Poly1305(key=key),
]
CLIENT = Socks5_TCP_Retranslator(
    config['remote_proxy_host'], int(config['remote_proxy_port']),
    cipher_index=3,
    ciphers=available_ciphers,
    udp_cipher=available_ciphers[2],
    username=config['username'],
    password=config['password'],
)
# CLIENT.logger.addHandler(file_handler)
CLIENT.listen_and_forward(local_host=config['local_proxy_host'], local_port=int(config['local_proxy_port']))