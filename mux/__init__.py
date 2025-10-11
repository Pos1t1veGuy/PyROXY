from pyroxy import Cipher
from typing import *
import asyncio

from .core import TCP_MuxSession, MuxStream
from ..proxy_client import Socks5_TCP_Retranslator
from ..proxy_server import Socks5Server


class Socks5_TCP_Mux_Retranslator(Socks5_TCP_Retranslator):
    def __init__(self, *args, mux_workers: int = 1, **kwargs):
        super().__init__(*args, **kwargs)
        self.mux_workers = mux_workers
        self.mux_sessions = []

    async def async_listen_and_forward(self, local_host: str = '127.0.0.1', local_port: int = 1080):
        for i in range(self.mux_workers):
            tcp_session = await self.handshake(
                proxy_host=self.remote_host, proxy_port=self.remote_port, username=self.username, password=self.password
            )
            self.mux_sessions.append(
                TCP_MuxSession(tcp_session.reader, tcp_session.writer, tcp_session.cipher, self.remote_host,
                               self.remote_port, mux_name=f'MuxSession{i}')
            )

        asyncio.create_task(self.monitor_mux())
        await super().async_listen_and_forward(local_host=local_host, local_port=local_port)


    async def monitor_mux(self):
        while True:
            for i, session in enumerate(list(self.mux_sessions)):
                if session.closed:
                    self.logger.warning(f"Reconnecting MUX {i}...")
                    tcp_session = await self.handshake(proxy_host=self.remote_host, proxy_port=self.remote_port,
                                                       username=self.username, password=self.password)
                    self.mux_sessions[i] = TCP_MuxSession(tcp_session.reader, tcp_session.writer, tcp_session.cipher,
                                                          self.remote_host, self.remote_port, mux_name=f"MuxSession{i}")
            await asyncio.sleep(3)

    async def handle_local_client(self, client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter):
        try:
            addr, port, command, default_cipher, user = await self.listen_local_cmd(client_reader, client_writer)
        except Exception as e:
            self.logger.error(
                f"Can not do handshake to local proxy {self.local_server.host}:{self.local_server.port} — {e}"
            )
            return

        try:
            remote_stream = await self.mux_sessions[0].open_stream() # Потом надо распределить и открывать стрим в самой незабитой сессии
            # mux = min(self.mux_sessions, key=lambda s: len(s.streams))
            # remote_stream = await mux.open_stream()
            self.logger.debug('Client handshaked with remote server')
        except ConnectionRefusedError:
            self.logger.error(f"Can not connect to remote proxy {self.remote_host}:{self.remote_port}")
            return
        except Exception as e:
            self.logger.error(f"Can not do handshake to remote proxy {self.remote_host}:{self.remote_port} — {e}")
            return

        # try:
        status_code = await command(user, addr, port, default_cipher, remote_stream, client_reader, client_writer)
        self.logger.debug(f"Connection to {addr}:{port} is closed, code: {status_code}")
        await self.close_writer(client_writer)
        # except Exception as e:
        #     self.logger.error(f"Running client cmd error {self.remote_host}:{self.remote_port} — {e}")
        #     return


class Mux_Socks5Server(Socks5Server):
    async def proxy_client(self, user: 'User', cipher: Cipher, proxying_mode: int,
                     reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> int:
        match proxying_mode:
            case 0: # default mode
                addr, port, command = await self.trace_event(
                    cipher.server_handle_command(self.socks_version, self.user_commands, reader),
                    event_name=f'HANDLE_CLIENT_CMD'
                )
                self.logger.info(f'Client {user} sent command {command.__qualname__} to {addr}:{port}')

                if command == ConnectionMethods.UDP_ASSOCIATE:
                    if user.username in self.clients_udp_servers.keys():
                        if self.clients_udp_servers[user.username] >= self.max_udp_for_user:
                            self.logger.warning(f"Too many UDP connections for {addr}:{port} - {self.max_udp_for_user}")
                            reply_frames = await self.trace_event(
                                cipher.server_make_reply(self.socks_version, REPLYES_CODES['not_allowed'], '0.0.0.0', 0),
                                event_name=f'CMD_CONFIRM'
                            )
                            writer.write(b''.join(reply_frames))
                            await writer.drain()
                            return 1

                        self.clients_udp_servers[user.username] += 1
                    else:
                        self.clients_udp_servers[user.username] = 1

                result_code, traffic_stats = await self.trace_event(
                    command(self, addr, port, user, cipher, reader, writer),
                    event_name=f'RUNNING_CLIENT_CMD'
                )

                if command == ConnectionMethods.UDP_ASSOCIATE and user.username in self.clients_udp_servers.keys():
                    if self.clients_udp_servers[user.username] <= 1:
                        self.clients_udp_servers.pop(user.username)
                    else:
                        self.clients_udp_servers[user.username] -= 1

                return result_code

            case 1: # Mux mode
                mux_session = TCP_MuxSession(reader, writer, cipher, user.ip, user.port, user=user,
                                             mux_name=f'Mux_{user.username}_session', handle_stream=self.handle_stream,
                                             create_new_streams_in_read_loop=True)
                return 0

            case _:
                reply_frames = await self.trace_event(
                    cipher.server_make_reply(self.socks_version, REPLYES_CODES['not_allowed'], '0.0.0.0', 0),
                    event_name=f'CMD_CONFIRM'
                )
                writer.write(b''.join(reply_frames))
                await writer.drain()
                return 1

    async def handle_stream(self, stream: MuxStream):
        try:
            self.logger.info(f"[MUX] Session created at {self.mux_name} ({self.address_str})")
            addr, port, command = await self.trace_event(
                stream.cipher.server_handle_command(self.socks_version, self.user_commands, stream.reader),
                event_name=f'HANDLE_CLIENT_CMD'
            )
            self.logger.info(f'[MUX] Client {stream.mux.user} sent command {command.__qualname__} to {addr}:{port}')

            if command == ConnectionMethods.UDP_ASSOCIATE:
                if stream.mux.user.username in self.clients_udp_servers.keys():
                    if self.clients_udp_servers[stream.mux.user.username] >= self.max_udp_for_user:
                        self.logger.warning(f"Too many UDP connections for {addr}:{port} - {self.max_udp_for_user}")
                        reply_frames = await self.trace_event(
                            stream.cipher.server_make_reply(self.socks_version, REPLYES_CODES['not_allowed'], '0.0.0.0', 0),
                            event_name=f'CMD_CONFIRM'
                        )
                        await stream.asend(b''.join(reply_frames))
                        return 1

                    self.clients_udp_servers[stream.mux.user.username] += 1
                else:
                    self.clients_udp_servers[stream.mux.user.username] = 1

            result_code, traffic_stats = await self.trace_event(
                command(self, addr, port, stream.mux.user, stream.cipher, stream.reader, stream.writer),
                event_name=f'RUNNING_CLIENT_CMD'
            )

            if command == ConnectionMethods.UDP_ASSOCIATE and stream.mux.user.username in self.clients_udp_servers.keys():
                if self.clients_udp_servers[stream.mux.user.username] <= 1:
                    self.clients_udp_servers.pop(stream.mux.user.username)
                else:
                    self.clients_udp_servers[stream.mux.user.username] -= 1
        except asyncio.IncompleteReadError:
            self.logger.info(f"[MUX] Session {self.mux_name} ({self.address_str}) closed by peer")
            await self.close()
        except Exception as e:
            self.logger.error(f"[MUX] stream {stream.stream_id} error: {e}")
        finally:
            await stream.close()