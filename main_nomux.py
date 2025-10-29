import json
import os
import logging
import argparse
from pathlib import Path
from logging.handlers import TimedRotatingFileHandler

from pyroxy.proxy_server import Socks5Server
from pyroxy.ciphers import *
from pyroxy.db_handlers import SQLite_Handler
from pyroxy.wrappers import HTTP_WS_Wrapper, PP_HTTP_WS_Wrapper


parser = argparse.ArgumentParser(description="PyROXY server starter")
logging_levels = ['info', 'debug', 'warning', 'error']
logging_levels += [level.upper() for level in logging_levels]
parser.add_argument("--logging", choices=logging_levels, default='info', help="logging level")
parser.add_argument("--hosting", type=int, choices=[1,0], default=1, help="hosting mode")
parser.add_argument("--host", type=str, default='127.0.0.1', help="TCP host")
parser.add_argument("--udp_host", type=str, default='0.0.0.0', help="UDP host")
parser.add_argument("--port", type=int, default=8080, help="proxy server port")
parser.add_argument("--execute", type=str, help="Execute DB handler command, e.g. function(arg1, arg2, kwarg1) or simply help()")
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
    Cipher(wrapper=PP_HTTP_WS_Wrapper()), # starts a handshake with client_hello and server_hello from wrapper
    AES_CTR(key=key, iv=os.urandom(16)),
    ChaCha20_Poly1305(key=key),
    Cipher()
]
SERVER = Socks5Server(
    db_handler=SQLite_Handler(filepath=db_file),
    ciphers=available_ciphers,
    udp_cipher=available_ciphers[2].copy(),
    port=args.port,
    host=args.host,
    udp_host=args.udp_host,
)

if args.execute:
    allowed_funcs = {}

    for name, attr in inspect.getmembers(SERVER.db_handler):
        if name.startswith("_"):
            continue
        if callable(attr):
            allowed_funcs[name] = attr

    def print_help() -> int:
        print("Available DB commands:\n")
        i = 0
        for name, func in allowed_funcs.items():
            i += 1
            if name == "help":
                continue
            sig = inspect.signature(func)
            ann = inspect.getdoc(func) or ""
            print(f"  {' ' if i < 10 else ''}{i}. {name}{sig}")
            if ann:
                print(f"    → {ann.splitlines()[0]}")
        print("\nExample usage: --execute \"is_superuser('admin')\"")
        return 0

    allowed_funcs['help'] = print_help


    print('executing database command')
    result = eval(
        f"allowed_funcs['{args.execute.split('(')[0]}']{args.execute[len(args.execute.split('(')[0]):]}",
        {"allowed_funcs": allowed_funcs}
    )
    print('result:', result)
    sys.exit(0)

SERVER.logger.setLevel(getattr(logging, args.logging.upper(), logging.INFO))

SERVER.logger.addHandler(file_handler)
try:
    asyncio.run(SERVER.start())
except KeyboardInterrupt:
    SERVER.logger.info('Server closed')