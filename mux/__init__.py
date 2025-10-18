from pyroxy import Cipher
from typing import *
import asyncio
import traceback
import logging
import time

from .core import TCP_MuxSession, MuxStream
from ..proxy_client import Socks5_TCP_Retranslator, TCP_ProxySession
from ..proxy_server import Socks5Server, ConnectionMethods, User


class Socks5_TCP_Mux_Retranslator(Socks5_TCP_Retranslator):
    def __init__(self, *args, min_mux_workers: int = 3, max_mux_workers: int = 15, max_streams_in_session: int = 8,
                 session_timeout: int = 30, stream_timeout: int = 10*60, mux_monitor_delay: int = 5, **kwargs):
        super().__init__(*args, **kwargs)
        self.min_mux_workers = min_mux_workers
        self.max_mux_workers = max_mux_workers
        self.max_streams_in_session = max_streams_in_session
        self.mux_monitor_delay = mux_monitor_delay
        self.session_timeout = session_timeout
        self.stream_timeout = stream_timeout
        self.mux_sessions: List[TCP_MuxSession] = []
        self._session_lock = asyncio.Lock()
        self._mux_lock = asyncio.Lock()
        self.closing = False

    async def async_listen_and_forward(self, local_host: str = '127.0.0.1', local_port: int = 1080):
        try:
            self.server_is_available = await self.ping()
            if self.server_is_available:
                for i in range(self.min_mux_workers):
                    self.mux_sessions.append(
                        (await self.open_mux_connection(always_alive=True, mux_name=f'MuxSession{i}'))[1]
                    )

                asyncio.create_task(self.monitor_mux())
                await super().async_listen_and_forward(local_host=local_host, local_port=local_port, ping=False)
            else:
                self.logger.error(f"Server is not available {self.remote_host}:{self.remote_port}")

        except KeyboardInterrupt:
            self.logger.info('Client closed by user')
        except RuntimeError:
            self.logger.info('Client closed by user')


    async def monitor_mux(self):
        while not self.closing:
            try:
                ping_count = 0
                while (await self.ping()) <= 0:
                    if ping_count == 4:
                        self.logger.error('Server is unavailable')
                        async with self._mux_lock:
                            for session in self.mux_sessions:
                                await session.close()

                    ping_count += 1
                    await asyncio.sleep(self.mux_monitor_delay)
                    continue

                async with self._mux_lock:
                    now = time.time()
                    for i, session in enumerate(list(self.mux_sessions)):
                        if session.closed:
                            if session.always_alive:
                                self.logger.debug(f"Reconnecting MUX {i}...")
                                self.mux_sessions[i] = (await self.open_mux_connection(mux_name=f'MuxSession{i}'))[1]
                            else:
                                self.mux_sessions.pop(i)
                        elif self.session_timeout <= now - session.last_activity_time:
                            if session.always_alive:
                                self.logger.debug(f"Reconnecting MUX {i}...")
                                self.mux_sessions[i] = (await self.open_mux_connection(mux_name=f'MuxSession{i}'))[1]
                            else:
                                await session.close()

                await asyncio.sleep(self.mux_monitor_delay)
            except Exception as ex:
                if self.logger.isEnabledFor(logging.DEBUG):
                    traceback.print_exc()
                self.logger.debug(f'monitor_mux received as error: {ex}')


    async def handle_local_client(self, client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter):
        try:
            addr, port, command, default_cipher, user = await self.listen_local_cmd(client_reader, client_writer)
        except Exception as e:
            self.logger.error(
                f"Can not do handshake to local proxy {self.local_server.host}:{self.local_server.port} — {e}"
            )
            return

        async with self._mux_lock:
            try:
                mux = await self.get_strongest_session()
                remote_stream = await mux.open_stream()
                self.logger.debug(f'MUX Stream is opened in {mux}')
            except ConnectionRefusedError:
                self.logger.error(f"Can not connect to remote proxy {self.remote_host}:{self.remote_port}")
                return
            except Exception as e:
                self.logger.error(f"Can not do handshake to remote proxy {self.remote_host}:{self.remote_port} — {e}")
                return

        try:
            status_code = await command(user, addr, port, default_cipher, remote_stream, client_writer, client_reader)
            self.logger.debug(f"Connection to {addr}:{port} is closed, code: {status_code}")
            await self.close_writer(client_writer)
        except Exception as e:
            if self.logger.isEnabledFor(logging.DEBUG):
                traceback.print_exc()
            self.logger.error(f"Running client cmd error {self.remote_host}:{self.remote_port} — {e}")
            return

    async def open_mux_connection(self, **kwargs) -> Tuple[TCP_ProxySession, TCP_MuxSession]:
        async with self._session_lock:
            tcp_session = await self.handshake(
                proxy_host=self.remote_host, proxy_port=self.remote_port, username=self.username, password=self.password,
                proxying_mode=1,
            )
            mux_session = TCP_MuxSession(
                tcp_session.reader, tcp_session.writer, tcp_session.cipher, self.remote_host, self.remote_port, **kwargs
            )
            return tcp_session, mux_session

    async def ping(self, timeout: int = 5) -> float:
        async with self._mux_lock:
            mux = await self.get_strongest_session()
            remote_stream = await mux.open_stream()
        user = User.get_empty_user(cipher=Cipher())
        time_start = time.time()

        try:
            async with asyncio.timeout(5):
                status_code = await self.PING(user, user.ip, user.port, user.cipher, remote_stream, ..., ...)
                if status_code == 0:
                    return time.time() - time_start
                raise ConnectionError('Server is unavailable')
        except asyncio.TimeoutError:
            raise ConnectionError("Ping timeout")
        finally:
            await remote_stream.close()

    async def get_strongest_session(self, create_new: bool = True) -> Optional[TCP_MuxSession]:
        if not self.mux_sessions:
            if create_new:
                _, mux = await self.open_mux_connection(mux_name=f'MuxSession{len(self.mux_sessions)}_temp')
                self.mux_sessions.append(mux)
                return mux
            else:
                return

        mux = min(self.active_mux_sessions, key=lambda s: len(s.streams))
        if len(mux.streams) >= self.max_streams_in_session and len(self.active_mux_sessions) < self.max_mux_workers and create_new:
            _, mux = await self.open_mux_connection(mux_name=f'MuxSession{len(self.mux_sessions)}_temp')
            self.mux_sessions.append(mux)

        return mux

    @property
    def active_mux_sessions(self) -> TCP_MuxSession:
        return [mux for mux in self.mux_sessions if not mux.closed]

class Mux_Socks5Server(Socks5Server):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.mux_sessions: Dict[str, List[TCP_MuxSession]] = {}
        self._mux_lock = asyncio.Lock()

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
                async with self._mux_lock:
                    muxes = self.mux_sessions.get(user.username, [])
                    session = TCP_MuxSession(
                        reader, writer, cipher, user.ip, user.port,
                        user=user, start_reader=False, mux_name=f'Mux_{user.username}_session{len(muxes)}',
                        handle_stream=self.handle_stream, create_new_streams_in_read_loop=True
                    )
                    muxes.append(session)
                    self.mux_sessions[user.username] = muxes

                try:
                    await session.read_loop()
                finally:
                    async with self._mux_lock:
                        muxes = self.mux_sessions.get(user.username, [])
                        if session in muxes:
                            muxes.remove(session)
                            if not muxes:
                                self.mux_sessions.pop(user.username, None)
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
            self.logger.info(f"[MUX] Stream created at {stream.mux.mux_name} ({stream.mux.address_str})")
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
        except (asyncio.IncompleteReadError, ConnectionResetError, ConnectionError):
            self.logger.info(f"[MUX] Session {stream.mux.mux_name} ({stream.mux.address_str}) closed by peer")
            await self.close()
        except Exception as e:
            if self.logger.isEnabledFor(logging.DEBUG):
                traceback.print_exc()
            self.logger.error(f"[MUX] stream {stream.stream_id} error: {e}")
        finally:
            await stream.close()