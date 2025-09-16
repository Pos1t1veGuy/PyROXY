import argparse
import logging
import os
import threading
import ctypes, sys
import signal
import subprocess
from pathlib import Path
from logging.handlers import TimedRotatingFileHandler

from pyroxy.proxy_client import Socks5_TCP_Retranslator
from pyroxy.ciphers import *
from pyroxy.wrappers import HTTP_WS_Wrapper
from pyroxy.tunnel import Tun2Socks


APP_VERSION = '1.0.0'


def make_log(filename: str):
    log_file = Path(__file__).parent / 'logs' / filename
    os.makedirs(log_file.parent, exist_ok=True)

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
    return file_handler


def main():
    parser = argparse.ArgumentParser(
        description="PyROXY - makes encrypted connection to pyroxy socks5 server with selested user cipher and wrapper"
    )
    ciphers_choices = ["none", "aes_ctr", "chacha20", "default"]
    logging_levels = ['info', 'debug', 'warning', 'error']

    parser.add_argument(
        "--version",
        action="version",
        version=APP_VERSION
    )

    parser.add_argument("--host", required=True, help="PyROXY server host")
    parser.add_argument("--port", type=int, default=80, help="PyROXY server port (by default 80)")
    parser.add_argument("--username", required=True, help="Your username registered on the PyROXY server")
    parser.add_argument("--password", required=True, help="Your password registered on the PyROXY server")
    parser.add_argument("--key", required=True, help="PyROXY server hex key")
    parser.add_argument("--default_key", help="PyROXY server handshake hex key")

    parser.add_argument("--cipher", choices=ciphers_choices, default="none", help="Selected cipher")
    parser.add_argument("--udp_cipher", choices=ciphers_choices, default="chacha20", help="Selected cipher")

    parser.add_argument("--local_host", default='127.0.0.1', help="Local client (retranslator) host")
    parser.add_argument("--local_port", type=int, default=1080, help="Local client (retranslator) port")

    parser.add_argument("--log_file", type=int, choices=[1,0], default=0, help="Enable logger file (0 - false, 1 - true)")
    parser.add_argument("--tunnel_debug", type=int, choices=[1,0], default=0, help="Enable tunnel log (0 - false, 1 - true)")
    parser.add_argument("--logging_level", choices=logging_levels, default='info', help="Application logging level")

    parser.add_argument("--tun2socks_path", default=Path(__file__).parent / "tun2socks.exe",
                        help="Path to tun2socks.exe tunnel interface (wintun.dll there required)")

    parser.add_argument(
        "--auto_forward_traffic",
        type=int,
        choices=[0,1],
        default=1,
        help="Automatically forward all TCP traffic to local SOCKS5 (0 - false, 1 - true) (default: 1)"
    )

    args = parser.parse_args()

    tunnel = Tun2Socks(args.host, path_to_exe=args.tun2socks_path, silent=not bool(args.tunnel_debug))
    if args.auto_forward_traffic == 1:
        tunnel.stop() # to delete broken routes
        print('[+] auto forward enabled')
        tunnel.start(args.local_host, args.local_port)

    if args.key == '.':
        print('[e] You need to input your KEY into "--key=..."')
        sys.exit(1)
    elif args.username == '.':
        print('[e] You need to input your USERNAME into "--username=..."')
        sys.exit(1)
    elif args.password == '.':
        print('[e] You need to input your PASSWORD into "--password=..."')
        sys.exit(1)
    elif args.host == '.':
        print('[e] You need to input server HOST into "--host=..."')
        sys.exit(1)

    '''
    You can't mix up this order "available_ciphers" of ciphers, otherwise the server and client will mix up their
    ciphers and the connection will fail.
    '''
    key = bytes.fromhex(args.key)
    default_key = bytes.fromhex(args.default_key)
    available_ciphers = [
        Cipher(wrapper=HTTP_WS_Wrapper()),  # starts a handshake with client_hello and server_hello from wrapper
        AES_CTR(key=default_key, iv=os.urandom(16)),
        ChaCha20_Poly1305(key=default_key),
        Cipher(), # without wrapper
    ]

    try:
        CLIENT = Socks5_TCP_Retranslator(
            args.host, int(args.port),
            cipher_index=ciphers_choices.index(args.cipher),
            ciphers=available_ciphers,
            udp_cipher=available_ciphers[ciphers_choices.index(args.udp_cipher)].copy(),
            username=args.username,
            password=args.password,
            cipher_key=key,
        )

        CLIENT.logger.setLevel(getattr(logging, args.logging_level.upper(), logging.INFO))
        if args.log_file == 1:
            CLIENT.logger.addHandler(make_log("client.log"))

        CLIENT.listen_and_forward(local_host=args.local_host, local_port=args.local_port)
    except KeyboardInterrupt:
        pass
    except Exception as ex:
        print(f'[e] {ex}')
    finally:
        print('[+] client closed')

    return tunnel


if __name__ == "__main__":
    signal.signal(signal.SIGINT, lambda sig, frame: sys.exit(0))
    signal.signal(signal.SIGTERM, lambda sig, frame: sys.exit(0))
    tunnel = main()
    tunnel.stop()