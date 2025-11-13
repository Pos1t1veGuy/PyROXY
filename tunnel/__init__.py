from typing import *
import subprocess
import os, sys
import signal
import time
import re
import ipaddress
import netifaces
import json
import socket
import psutil
import asyncio
import platform
import threading as th
import concurrent.futures
import traceback
from pathlib import Path
from colorama import init, Fore, Style, init
init()

from ..utils import resolve_domain_doh


class Tun2Socks:
    def __new__(cls, *args, **kwargs):
        if cls is Tun2Socks:
            system = platform.system().lower()
            if system == "windows":
                return Tun2Socks_Windows(*args, **kwargs)
            else:
                return Tun2Socks_Linux(*args, **kwargs)
        return object.__new__(cls)

    def __init__(self, socks_ext: str, tun_name: str = "wintun", interface_ip: str = '10.0.0.1', white_list: List[str] = [],
                 black_list: List[str] = [], path_to_exe: Optional[str] = None, interface_mask: str = '255.255.255.255',
                 silent: bool = True):
        if platform.system().lower() == "windows":
            self.path_to_exe = Path(path_to_exe) if path_to_exe else Path(__file__).parent / "tun2socks.exe"
        else:
            self.path_to_exe = Path(path_to_exe) if path_to_exe else Path(__file__).parent / "tun2socks_linux"
        self.tun_name = tun_name
        self.interface_ip = interface_ip
        self.interface_mask = interface_mask
        self.socks_ext = socks_ext
        self.silent = silent
        self.white_list = white_list
        self.black_list = black_list
        self.domain_ip_white_dict: Dict[str, str] = {}
        self.domain_ip_black_dict: Dict[str, str] = {}

        for black_addr in self.black_list:
            if black_addr in self.white_list:
                self.white_list.remove(black_addr)

    def tun_started(self) -> bool:
        interfaces = self.get_interfaces()
        return interfaces.get(self.tun_name) != None

    def cmd_run(self, cmd: str, clear: bool = True):
        if clear:
            subprocess.run(cmd, shell=True, text=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            print(cmd)
            subprocess.run(cmd, shell=True, text=True)

    def kill_process_by_name(self, name: str):
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                if proc.info['name'] and proc.info['name'].lower() == name.lower():
                    print(f"Terminating {proc.info['name']} (PID: {proc.info['pid']})")
                    proc.terminate()
                    proc.wait(timeout=3)
            except (psutil.NoSuchProcess, psutil.ZombieProcess):
                pass

    def get_used_ips(self) -> Set[str]:
        used = set()
        for iface in netifaces.interfaces():
            addrs = netifaces.ifaddresses(iface).get(netifaces.AF_INET, [])
            for addr in addrs:
                used.add(addr['addr'])
        return used

    def find_free_ip(self, net_str: str, mask: str) -> Tuple[str, str]:
        used_ips = self.get_used_ips()

        net = ipaddress.IPv4Network(f'{net_str}/{mask}', strict=False)

        for iface in netifaces.interfaces():
            addrs = netifaces.ifaddresses(iface).get(netifaces.AF_INET, [])
            for addr in addrs:
                other_net = ipaddress.IPv4Network(f"{addr['addr']}/{addr['netmask']}", strict=False)
                if net.overlaps(other_net):
                    break

            for ip in net.hosts():
                if str(ip) not in used_ips:
                    return str(ip), str(net.netmask)


class Tun2Socks_Windows(Tun2Socks):
    gateway_ip = None
    def_iface_id = None
    iface_id = None
    tun_proc = None
    updater_threads: List[th.Thread] = []
    bad_routes: List[str] = []

    def get_interfaces(self) -> dict:
        out = subprocess.check_output("netsh interface ipv4 show interfaces",
                                      shell=True, stderr=subprocess.DEVNULL, text=True, encoding="cp866")
        interfaces = {}
        for line in out.splitlines():
            m = re.match(r"\s*(\d+)\s+(\d+)\s+\w+\s+\w+\s+(.+)", line)
            if m:
                idx, metric, name = m.groups()
                interfaces[name.strip()] = {"idx": int(idx), "metric": int(metric)}
        return interfaces

    def get_interface_index_by_gateway(self, gateway_ip: str) -> Optional[List[int]]:
        ps_command = f"""
        Get-NetRoute -DestinationPrefix "0.0.0.0/0" |
        Where-Object {{ $_.NextHop -eq '{gateway_ip}' }} |
        Select-Object ifIndex, NextHop |
        ConvertTo-Json
        """
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_command],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )

        if result.returncode != 0:
            raise RuntimeError("Ошибка PowerShell: " + result.stderr)

        try:
            data = json.loads(result.stdout)
            if isinstance(data, list):
                return [entry["ifIndex"] for entry in data]
            elif isinstance(data, dict):
                return [data["ifIndex"]]
        except json.JSONDecodeError:
            return None

    def add_route(self, ip: str, gataway_ip: str, interface_id: int, mask: str = '255.255.255.255', metric: int = 1):
        self.cmd_run(f'route add {ip} mask {mask} {gataway_ip} metric {metric} if {interface_id}')
    def delete_route(self, ip: str, gataway_ip: str, interface_id: int, mask: str = '255.255.255.255'):
        self.cmd_run(f'route delete {ip} mask {mask} {gataway_ip} metric 1 if {interface_id}')

    def get_ip_by_domain(self, domain_or_ip: str, return_ttl: bool = False) -> Tuple[Optional[str], Optional[str]]:
        if re.match(r'^\d+\.\d+\.\d+\.\d+$', domain_or_ip):  # IPv4
            return domain_or_ip, domain_or_ip
        else:  # domain
            try:
                return domain_or_ip, *resolve_domain_doh(domain_or_ip, return_ttl=return_ttl)
            except socket.gaierror:
                pass
        return None, None

    def thread_domain_resolve(self, domain_list: List[str], return_ttl: bool = False) -> List[Tuple[Optional[str]]]:
        resolved_domains = [None] * len(domain_list)
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(20, len(domain_list))) as executor:
            futures = {
                executor.submit(self.get_ip_by_domain, host, return_ttl=return_ttl): i
                for i, host in enumerate(domain_list)
            }
            for future in concurrent.futures.as_completed(futures):
                idx = futures[future]
                try:
                    resolved_domains[idx] = future.result()
                except Exception as e:
                    resolved_domains[idx] = (None, None)
                    print(f'{Fore.RED}[!] Failed to resolve domain "{domain_list[idx]}": {e}{Style.RESET_ALL}')

        return resolved_domains

    def update_routes(self, domain_list: List[str], ips_dict: Dict[str, str], interface_ip: str, interface_id: int,
                      auto_update: bool = False, metric: int = 1, mode: str = 'via'):
        ips_list = self.thread_domain_resolve(domain_list, return_ttl=auto_update) if domain_list else []

        for i, host in enumerate(domain_list):
            domain, ip, ttl = ips_list[i]
            if domain and ip:
                old_ip = ips_dict.get(host)
                if old_ip != ip:
                    if old_ip:
                        self.delete_route(old_ip, interface_ip, interface_id)
                    self.add_route(ip, interface_ip, interface_id, metric=metric)
                    ips_dict[domain] = ip

                    if host in self.bad_routes:
                        self.bad_routes.remove(host)
                    if auto_update:
                        thread = th.Thread(target=self.domain_auto_resolver, args=(
                            domain, old_ip, ttl, ips_dict, interface_ip, interface_id
                        ), kwargs={'metric': metric}, daemon=True)
                        self.updater_threads.append(thread)
                        thread.start()
                    print(f'[+] {"Rerouted" if old_ip else "Routed"} "{host}" ({ip}) {mode} tunnel')

            elif not host in self.bad_routes:
                print(f'{Fore.RED}[!] Failed to route "{host}": {e}{Style.RESET_ALL}')
                self.bad_routes.append(host)

    def domain_auto_resolver(self, domain: str, old_ip: str, ttl: int, ips_dict: Dict[str, str], interface_ip: str,
                             interface_id: int, metric: int = 1):
        while True:
            try:
                time.sleep(max(ttl - 5, 5))
                domain, ip, ttl = self.get_ip_by_domain(domain, return_ttl=True)
                if old_ip:
                    self.delete_route(old_ip, interface_ip, interface_id)
                self.add_route(ip, interface_ip, interface_id, metric=metric)
                ips_dict[domain] = ip

                if domain in self.bad_routes:
                    self.bad_routes.remove(domain)
                old_ip = ip
                print(f'[+] {"Rerouted" if old_ip else "Routed"} "{domain}" ({ip}) via tunnel')
            except Exception as e:
                print(f'{Fore.RED}[!] Auto resolver error for "{domain}": {e}{Style.RESET_ALL}')
                time.sleep(60)


    def start(self, socks_local: str = '127.0.0.1', socks_local_port: int = 1080, resolver_urls: List[str] = [],
              auto_update: bool = False):
        if self.tun_proc: return

        if self.tun_started():
            self.kill_process_by_name(self.path_to_exe.name)

        if self.silent:
            self.tun_proc = subprocess.Popen([
                self.path_to_exe,
                "-device", f"tun://{self.tun_name}",
                "-proxy", f"socks5://{socks_local}:{socks_local_port}",
            ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            self.tun_proc = subprocess.Popen([
                self.path_to_exe,
                "-device", f"tun://{self.tun_name}",
                "-proxy", f"socks5://{socks_local}:{socks_local_port}",
            ])
        time.sleep(1)

        gws = netifaces.gateways()
        default_gateway = gws.get('default', {}).get(netifaces.AF_INET)
        if not default_gateway:
            print(f'{Fore.RED}[e] can not find LAN gateway IP{Style.RESET_ALL}')
            sys.exit(1)

        self.gateway_ip, interface_name = default_gateway
        self.def_iface_id = self.get_interface_index_by_gateway(self.gateway_ip)[0]
        if not self.def_iface_id:
            print(f'{Fore.RED}[e] can not find LAN gateway id by IP {self.gateway_ip}{Style.RESET_ALL}')
            sys.exit(1)

        self.add_route(self.socks_ext, self.gateway_ip, self.def_iface_id)
        self.interface_ip, self.interface_mask = self.find_free_ip(self.interface_ip, self.interface_mask)

        self.cmd_run(
            f'netsh interface ip set address "{self.tun_name}" static {self.interface_ip} mask={self.interface_mask}'
        )
        self.cmd_run(f'netsh interface ip set interface "{self.tun_name}" metric=1')

        interfaces = self.get_interfaces()
        try:
            self.iface_id = interfaces[self.tun_name]["idx"]
        except KeyError:
            print(f'{Fore.RED}[e] tun2socks "{self.tun_name}" interface not found{Style.RESET_ALL}')
            sys.exit(1)

        if self.white_list in ([], ['']):
            if not self.black_list in ([], ['']):
                self.update_routes(self.black_list, self.domain_ip_black_dict, self.gateway_ip, self.def_iface_id,
                                   auto_update=auto_update, mode='out of')
            self.add_route('0.0.0.0', self.interface_ip, self.iface_id, mask='0.0.0.0')
            print(f'[+] Routed all ips via tun2socks tunnel')
        else:
            self.update_routes(self.white_list, self.domain_ip_white_dict, self.interface_ip, self.iface_id,
                               auto_update=auto_update)

    def stop(self):
        if self.white_list in ([], ['']):
            self.delete_route('0.0.0.0', self.interface_ip, self.iface_id, mask='0.0.0.0')
        else:
            for ip in self.domain_ip_white_dict.values():
                self.delete_route(ip, self.interface_ip, self.iface_id)
        self.delete_route(self.socks_ext, self.gateway_ip, self.def_iface_id)
        for ip in self.domain_ip_black_dict.values():
            self.delete_route(ip, self.gateway_ip, self.def_iface_id)

        if not self.tun_proc: return

        try:
            os.kill(self.tun_proc.pid, signal.SIGTERM)
            self.tun_proc = None
        except PermissionError:
            pass


class Tun2Socks_Linux(Tun2Socks):
    def _ensure_executable(self):
        try:
            mode = self.path_to_exe.stat().st_mode
            if not (mode & 0o111):
                self.path_to_exe.chmod(mode | 0o755)
        except Exception:
            pass

    def get_interfaces(self) -> dict:
        """
        Returns dictionary mapping interface name -> dict(info)
        We'll use "idx" (ifindex) and addresses by parsing 'ip -o link' and 'ip -o -4 addr'
        """
        interfaces = {}
        # get ifindex and state
        out = self.cmd_run("ip -o link", clear=True).stdout
        for line in out.splitlines():
            # format: "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000"
            m = re.match(r'^\s*(\d+):\s*([^:]+):\s*(.*)$', line)
            if m:
                idx = int(m.group(1))
                name = m.group(2)
                interfaces[name] = {"idx": idx}
        # fill ipv4 addresses
        out = self.cmd_run("ip -o -4 addr show", clear=True).stdout
        for line in out.splitlines():
            # example: "2: eth0    inet 192.168.1.10/24 brd 192.168.1.255 scope global eth0"
            m = re.match(r'^\s*\d+:\s*([^ ]+)\s+inet\s+([^/]+)/(\d+)', line)
            if m:
                name = m.group(1)
                ip = m.group(2)
                if name in interfaces:
                    interfaces[name].setdefault("addrs", []).append(ip)
        return interfaces

    def get_default_gateway(self) -> Tuple[Optional[str], Optional[str]]:
        """
        Return (gateway_ip, interface_name) from `ip route show default`
        """
        out = self.cmd_run("ip route show default", clear=True).stdout
        # typical: "default via 192.168.1.1 dev eth0 proto dhcp metric 100"
        m = re.search(r'default via ([0-9\.]+) dev ([^\s]+)', out)
        if m:
            return m.group(1), m.group(2)
        return None, None

    def start(self, socks_local: str = '127.0.0.1', socks_local_port: int = 1080, resolver_urls: List[str] = []):
        if self.tun_proc: return

        if not self.path_to_exe.exists():
            print(f'{Fore.RED}[e] tun2socks binary not found: {self.path_to_exe}{Style.RESET_ALL}')
            raise FileNotFoundError(self.path_to_exe)

        self._ensure_executable()

        try:
            self.kill_process_by_name(self.path_to_exe.name)
        except:
            pass

        if self.silent:
            self.tun_proc = subprocess.Popen([
                self.path_to_exe,
                "-device", f"tun://{self.tun_name}",
                "-proxy", f"socks5://{socks_local}:{socks_local_port}",
            ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            self.tun_proc = subprocess.Popen([
                self.path_to_exe,
                "-device", f"tun://{self.tun_name}",
                "-proxy", f"socks5://{socks_local}:{socks_local_port}",
            ])

        time.sleep(1.0)

        gw, iface = self.get_default_gateway()
        if not gw or not iface:
            print(f'{Fore.RED}[e] can not find default gateway or interface (need root/CAP_NET_ADMIN){Style.RESET_ALL}')
            try:
                self.tun_proc.terminate()
            except Exception:
                pass
            raise RuntimeError('Cannot determine default gateway')

        self.gateway_ip = gw
        self.def_iface_name = iface

        self.cmd_run(f"ip link set dev {self.tun_name} up")
        ip_addr = f"{self.interface_ip}/32" if '.' in self.interface_mask else f"{self.interface_ip}/{self.interface_mask}"
        self.cmd_run(f"ip addr add {ip_addr} dev {self.tun_name} || true")

        try:
            if re.match(r'^\d+\.\d+\.\d+\.\d+$', self.socks_ext):
                server_ip = self.socks_ext
            else:
                server_ip = resolve_domain_doh(self.socks_ext)

            res = self.cmd_run(f"ip route add {server_ip}/32 via {self.gateway_ip} dev {self.def_iface_name}")
        except Exception as e:
            print(f"{Fore.RED}[!] Failed to add route to proxy server {self.socks_ext}: {e}{Style.RESET_ALL}")

        interfaces = self.get_interfaces()
        if self.tun_name not in interfaces:
            print(f'{Fore.RED}[!] Interface {self.tun_name} not found after starting tun2socks; '
                  f'continuing (some binaries create interface lazily).{Style.RESET_ALL}')
        else:
            print(f'[+] Tun interface {self.tun_name} (idx {interfaces[self.tun_name].get("idx")}) ready')

        if not self.white_list or self.white_list == ['']:
            try:
                self.cmd_run(f"ip route add 0.0.0.0/0 dev {self.tun_name} metric 1")
                print(f'[+] Routed all IPs via {self.tun_name}')
            except Exception as e:
                print(f'{Fore.RED}[!] Failed to add default route via {self.tun_name}: {e}{Style.RESET_ALL}')
        else:
            for host in self.white_list:
                try:
                    if re.match(r'^\d+\.\d+\.\d+\.\d+$', host):
                        ips = [host]
                    else:
                        ips = [resolve_domain_doh(host)]
                    for ip in ips:
                        try:
                            self.cmd_run(f"ip route add {ip}/32 dev {self.tun_name} metric 1")
                            print(f'[+] Routed "{host}" ({ip}) via {self.tun_name}')
                        except Exception as e:
                            print(f'{Fore.RED}[!] Failed to route \"{host}\" ({ip}): {e}{Style.RESET_ALL}')
                except Exception as e:
                    print(f'{Fore.RED}[!] Failed to route \"{host}\": {e}{Style.RESET_ALL}')

    def stop(self):
        gw, iface = self.get_default_gateway()
        if gw:
            self.gateway_ip = gw
        if iface:
            self.def_iface_name = iface

        try:
            self.cmd_run(f"ip route del default dev {self.tun_name}")
        except:
            pass

        try:
            if re.match(r'^\d+\.\d+\.\d+\.\d+$', self.socks_ext):
                server_ip = self.socks_ext
            else:
                server_ip = resolve_domain_doh(self.socks_ext)
            if self.gateway_ip and self.def_iface_name:
                self.cmd_run(f"ip route del {server_ip}/32 via {self.gateway_ip} dev {self.def_iface_name}")
        except:
            pass

        if self.white_list:
            for host in self.white_list:
                try:
                    if re.match(r'^\d+\.\d+\.\d+\.\d+$', host):
                        ips = [host]
                    else:
                        ips = [resolve_domain_doh(host)]
                    for ip in ips:
                        self.cmd_run(f"ip route del {ip}/32 dev {self.tun_name}")
                except:
                    pass

        if self.tun_proc and self.tun_proc.poll() is None:
            try:
                os.kill(self.tun_proc.pid, signal.SIGTERM)
                time.sleep(0.3)
                if self.tun_proc.poll() is None:
                    os.kill(self.tun_proc.pid, signal.SIGKILL)
            except:
                pass
        else:
            try:
                self.kill_process_by_name(self.path_to_exe.name)
            except Exception:
                pass

        self.tun_proc = None

        try:
            self.cmd_run(f"ip addr flush dev {self.tun_name}")
        except Exception:
            pass

        try:
            self.cmd_run(f"ip link set {self.tun_name} down")
        except Exception:
            pass


if __name__ == "__main__":
    try:
        tunnel = Tun2Socks()
        tunnel.start()
    except KeyboardInterrupt:
        tunnel.stop()
