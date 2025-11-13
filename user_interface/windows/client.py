import argparse
import logging
import os
import threading
import ctypes, sys
import signal
import subprocess
import ipaddress
import traceback
import socket
import asyncio
from pathlib import Path
from logging.handlers import TimedRotatingFileHandler
from colorama import init, Fore, Style, init
init()

from pyroxy.proxy_client import Socks5_TCP_Retranslator
from pyroxy.mux import Socks5_TCP_Mux_Retranslator
from pyroxy.ciphers import *
from pyroxy.wrappers import HTTP_WS_Wrapper
from pyroxy.tunnel import Tun2Socks
from pyroxy.utils import resolve_domain_doh


APP_VERSION = '1.1.0'


class ColorFormatter(logging.Formatter):
    COLORS = {
        logging.DEBUG: Fore.LIGHTBLACK_EX,
        logging.INFO: Fore.WHITE,
        logging.WARNING: Fore.YELLOW,
        logging.ERROR: Fore.RED,
        logging.CRITICAL: Fore.MAGENTA + Style.BRIGHT,
    }

    def format(self, record):
        color = self.COLORS.get(record.levelno, Fore.WHITE)
        asctime = self.formatTime(record, self.datefmt)
        return f"{color}[{asctime}] [{record.levelname}] {record.getMessage()}{Style.RESET_ALL}"


def make_loggers(filename: str):
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


    console_handler = logging.StreamHandler()
    console_formatter = ColorFormatter(
        fmt="[{asctime}] [{levelname}] {message}",
        datefmt="%H:%M:%S",
        style="{"
    )
    console_handler.setFormatter(console_formatter)
    return file_handler, console_handler

def read_list_file(filepath: str, comment: str = '# Put a domains or an IPs here') -> List[str]:
    if os.path.isfile(filepath):
        try:
            return [
                element for element in open(filepath, 'r').read().split('\n')
                if (not element.startswith('#')) and (not element.startswith(' #')) and (not element in ['', ' '])
            ]
        except Exception as ex:
            print(f'{Fore.RED}[e] Error when open white list file: {ex}{Style.RESET_ALL}')
    else:
        open(filepath, 'w').write(comment)


def main():
    tunnel = None
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

    parser.add_argument("--white_list_file", default='white_list.txt', help="List of domains or ips thats needs to proxy")
    parser.add_argument("--black_list_file", default='black_list.txt', help="List of domains or ips thats needs to ignore")
    parser.add_argument("--log_file", type=int, choices=[1, 0], default=0, help="Enable logger file (0 - false, 1 - true)")
    parser.add_argument("--tunnel_debug", type=int, choices=[1, 0], default=0, help="Enable tunnel log (0 - false, 1 - true)")
    parser.add_argument("--logging_level", choices=logging_levels, default='info', help="Application logging level")

    parser.add_argument("--tun2socks_path", default=Path(__file__).parent / "tun2socks.exe",
                        help="Path to tun2socks.exe tunnel interface (wintun.dll there required)")

    parser.add_argument(
        "--auto_forward_traffic",
        type=int,
        choices=[0, 1],
        default=1,
        help="Automatically forward all TCP traffic to local SOCKS5 (0 - false, 1 - true) (default: 1)"
    )

    args = parser.parse_args()

    try:
        white_list = read_list_file(args.white_list_file)
        black_list = read_list_file(args.black_list_file)

        remote_domain = ''
        try:
            ipa = ipaddress.ip_address(args.host)
            remote_host = args.host
        except ValueError:
            remote_host = resolve_domain_doh(args.host)
            remote_domain = args.host

        if args.key == '.':
            print(f'{Fore.RED}[e] You need to input your KEY into "--key=..."{Style.RESET_ALL}')
            sys.exit(1)
        elif args.username == '.':
            print(f'{Fore.RED}[e] You need to input your USERNAME into "--username=..."{Style.RESET_ALL}')
            sys.exit(1)
        elif args.password == '.':
            print(f'{Fore.RED}[e] You need to input your PASSWORD into "--password=..."{Style.RESET_ALL}')
            sys.exit(1)
        elif args.host == '.':
            print(f'{Fore.RED}[e] You need to input server HOST into "--host=..."{Style.RESET_ALL}')
            sys.exit(1)

        '''
        You can't mix up this order "available_ciphers" of ciphers, otherwise the server and client will mix up their
        ciphers and the connection will fail.
        '''
        key = bytes.fromhex(args.key)
        default_key = bytes.fromhex(args.default_key)
        available_ciphers = [
            Cipher(
                wrapper=HTTP_WS_Wrapper(host=remote_domain, server_ip=remote_host)
            ), # starts a handshake with client_hello and server_hello from wrapper
            AES_CTR(key=default_key, iv=os.urandom(16)),
            ChaCha20_Poly1305(key=default_key),
            Cipher(), # without wrapper
        ]

        CLIENT = Socks5_TCP_Mux_Retranslator(
            remote_host, int(args.port),
            remote_domain=remote_domain,
            cipher_index=ciphers_choices.index(args.cipher),
            ciphers=available_ciphers,
            udp_cipher=available_ciphers[ciphers_choices.index(args.udp_cipher)].copy(),
            username=args.username,
            password=args.password,
            cipher_key=key,
        )

        CLIENT.logger.setLevel(getattr(logging, args.logging_level.upper(), logging.INFO))
        file_log, console_log = make_loggers("client.log")
        CLIENT.logger.addHandler(console_log)
        if args.log_file == 1:
            CLIENT.logger.addHandler(file_log)
        CLIENT.logger.propagate = False

        tunnel = Tun2Socks(remote_host, white_list=white_list, black_list=black_list, path_to_exe=args.tun2socks_path,
                           silent=not bool(args.tunnel_debug))

        tunnel.stop() # to delete broken routes
        if args.auto_forward_traffic == 1:
            print(f'[+] Auto forward enabled')
            tunnel.start(args.local_host, args.local_port, auto_update=True)
        else:
            print(f'[+] Auto forward disabled, local proxy server works at {args.local_host}:{args.local_port}')

        CLIENT.listen_and_forward(local_host=args.local_host, local_port=args.local_port)

    except (KeyboardInterrupt, RuntimeError, asyncio.exceptions.CancelledError):
        pass
    except Exception as ex:
        if args.logging_level.lower() == "debug":
            print(f"{Fore.RED}[!] Full traceback:\n{traceback.format_exc()}")
        print(f'[e] {ex}{Style.RESET_ALL}')
    finally:
        print(f'[+] client closed')
        if tunnel:
            tunnel.stop()

    return tunnel

def shutdown(sig, frame):
    print(f"[+] Shutting down...")
    try:
        for task in asyncio.all_tasks():
            task.cancel()
    except RuntimeError:
        pass


if __name__ == "__main__":
    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)
    tunnel = main()
    if tunnel:
        tunnel.stop()