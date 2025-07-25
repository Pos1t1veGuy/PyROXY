from typing import *
from aioconsole import ainput

import asyncio
from .base_cipher import Cipher
from .proxy_server import Socks5Server

async def SERVER_GUI(host: str = '127.0.0.1', port: int = 1080,
                 user_white_list: Optional[Set[str]] = None,
                 users_black_list: Optional[Set[str]] = None,
                 cipher: Optional[Cipher] = None,
                 udp_cipher: Optional[Cipher] = None,
                 udp_server_timeout: int = 5*60,
                 users: Optional[Dict[str, str]] = None,
                 user_commands: Optional[Dict[bytes, callable]] = None,
                 accept_anonymous: bool = False,
                 log_bytes: bool = True):
    async with Socks5Server(host=host, port=port, user_white_list=user_white_list, users_black_list=users_black_list,
                 cipher=cipher, udp_cipher=udp_cipher, udp_server_timeout=udp_server_timeout, users=users,
                 user_commands=user_commands, accept_anonymous=accept_anonymous, log_bytes=log_bytes) as server:
        server.logger.info('ServerGUI started, type "ex" or "q" to close server')
        while 1:
            try:
                command = await ainput()
                cmdargs = command.split()
                cmd, args = cmdargs[0], cmdargs[1:]

                if cmd in ['ex','q','exit','quit']:
                    break

            except (KeyboardInterrupt, EOFError):
                break