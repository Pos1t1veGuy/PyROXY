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



tunnel_process = None


def start_tunnel():
    global tunnel_process
    tunnel_process = subprocess.Popen(
        ["hev-socks5-tunnel/hev-socks5-tunnel.exe", "config.yaml"],
        cwd="hev-socks5-tunnel",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )

def stop_tunnel():
    global tunnel_process
    if tunnel_process and tunnel_process.poll() is None:
        tunnel_process.terminate() # tunnel_process.kill()
        tunnel_process.wait()

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
    try:
        parser = argparse.ArgumentParser(
            description="PyROXY - makes encrypted connection to pyroxy socks5 server with selested user cipher and wrapper"
        )
        ciphers_choices = ["none", "aes_ctr", "aes_cbc", "chacha20"]

        parser.add_argument("--host", required=True, help="PyROXY server host")
        parser.add_argument("--port", type=int, default=80, help="PyROXY server port (by default 80)")
        parser.add_argument("--username", required=True, help="Your username registered on the PyROXY server")
        parser.add_argument("--password", required=True, help="Your password registered on the PyROXY server")
        parser.add_argument("--key", required=True, help="PyROXY server hex key")
        parser.add_argument("--default_key", help="PyROXY server handshake hex key")

        parser.add_argument("--cipher", choices=ciphers_choices, default="none", help="Selected cipher")
        parser.add_argument("--udp_cipher", choices=ciphers_choices, default="none", help="Selected cipher")

        parser.add_argument("--local_port", type=int, default=1080, help="Local client (retranslator) port")

        parser.add_argument("--log", type=int, choices=[1,0], default=0, help="Enable logger (0 - false, 1 - true)")
        parser.add_argument("--wrapper", choices=["none", "httpws"], default="httpws",
                            help="PyROXY server wrapper (proxy server disguise mode, by default httpws)")

        parser.add_argument(
            "--auto_forward_traffic",
            type=int,
            choices=[0,1],
            default=1,
            help="Automatically forward all TCP traffic to local SOCKS5 (0 - false, 1 - true) (default: 1)"
        )

        args = parser.parse_args()

        if args.auto_forward_traffic == 1:
            print('auto forward enabled')
            start_tunnel()

        if args.key == '.':
            print('ERROR: You need to put your KEY into starter.bat arguments "--key=..."')
            exit()
        elif args.username == '.':
            print('ERROR: You need to put your USERNAME into starter.bat arguments "--username=..."')
            exit()
        elif args.password == '.':
            print('ERROR: You need to put your PASSWORD into starter.bat arguments "--password=..."')
            exit()
        elif args.host == '.':
            print('ERROR: You need to put server HOST into starter.bat arguments "--host=..."')
            exit()

        '''
        You can't mix up this order "available_ciphers" of ciphers, otherwise the server and client will mix up their
        ciphers and the connection will fail.
        '''
        key = bytes.fromhex(args.key)
        default_key = bytes.fromhex(args.key)
        available_ciphers = [
            Cipher(wrapper=HTTP_WS_Wrapper()),  # starts a handshake with client_hello and server_hello from wrapper
            AES_CBC(key=default_key, iv=os.urandom(16)),
            AES_CTR(key=default_key, iv=os.urandom(16)),
            ChaCha20_Poly1305(key=default_key),
        ]

        CLIENT = Socks5_TCP_Retranslator(
            args.host, int(args.port),
            cipher_index=ciphers_choices.index(args.cipher),
            ciphers=available_ciphers,
            udp_cipher=available_ciphers[ciphers_choices.index(args.udp_cipher)],
            username=args.username,
            password=args.password,
            cipher_key=key,
        )
        if args.log == 1:
            CLIENT.logger.addHandler(make_log("client.log"))
        CLIENT.listen_and_forward(local_host='127.0.0.1', local_port=args.local_port)
    except KeyboardInterrupt:
        pass
    finally:
        print('client closed')
        stop_tunnel()


if __name__ == "__main__":
    signal.signal(signal.SIGINT, lambda sig, frame: sys.exit(0))
    signal.signal(signal.SIGTERM, lambda sig, frame: sys.exit(0))
    try:
        main()
    finally:
        stop_tunnel()