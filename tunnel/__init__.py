from typing import *
import subprocess
import os, sys
import signal
import time
import re
import ipaddress
import netifaces
import json
import psutil
import asyncio
from pathlib import Path

from ..base_cipher import resolve_doh


class Tun2Socks:
    gateway_ip = None
    def_iface_id = None
    tun_proc = None

    def __init__(self, socks_ext: str, tun_name: str = "wintun", interface_ip: str = '10.0.0.1', white_list: List[str] = [],
                 path_to_exe: Optional[str] = None, interface_mask: str = '255.255.255.255', silent: bool = True):
        self.path_to_exe = Path(path_to_exe) if path_to_exe else Path(__file__).parent / "tun2socks.exe"
        self.tun_name = tun_name
        self.interface_ip = interface_ip
        self.interface_mask = interface_mask
        self.socks_ext = socks_ext
        self.silent = silent
        self.white_list = white_list

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

    def get_interface_index_by_gateway(self, gateway_ip: str) -> Optional[list]:
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


    def start(self, socks_local: str = '127.0.0.1', socks_local_port: int = 1080, resolver_urls: List[str] = []):
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
            print('[e] can not find LAN gateway IP')
            sys.exit(1)

        self.gateway_ip, interface_name = default_gateway
        self.def_iface_id = self.get_interface_index_by_gateway(self.gateway_ip)[0]
        if not self.def_iface_id:
            print(f'[e] can not find LAN gateway id by IP {self.gateway_ip}')
            sys.exit(1)

        self.cmd_run(f'route add {self.socks_ext} mask 255.255.255.255 {self.gateway_ip} metric 1 if {self.def_iface_id}')
        self.interface_ip, self.interface_mask = self.find_free_ip(self.interface_ip, self.interface_mask)

        self.cmd_run(
            f'netsh interface ip set address "{self.tun_name}" static {self.interface_ip} mask={self.interface_mask}'
        )
        self.cmd_run(f'netsh interface ip set interface "{self.tun_name}" metric=1')

        interfaces = self.get_interfaces()
        try:
            iface_id = interfaces[self.tun_name]["idx"]
        except KeyError:
            print(f'[e] tun2socks "{self.tun_name}" interface not found')
            sys.exit(1)

        if self.white_list in ([], ['']):
            self.cmd_run(f'route add 0.0.0.0 mask 0.0.0.0 {self.interface_ip} metric 1 if {iface_id}')
            print(f'[+] Routed all ips via tun2socks tunnel')
        else:
            for host in self.white_list:
                try:
                    if re.match(r'^\d+\.\d+\.\d+\.\d+$', host):
                        ips = [host]
                    else:
                        ips = asyncio.run(resolve_doh(host, resolver_urls=resolver_urls))
                    for ip in ips:
                        self.cmd_run(f'route add {ip} mask 255.255.255.255 {self.interface_ip} metric 1 if {iface_id}')
                        print(f'[+] Routed "{host}" ({ip}) via tunnel')
                except Exception as e:
                    print(f'[!] Failed to route "{host}": {e}')


    def stop(self):
        try:
            interfaces = self.get_interfaces()
            iface_id = interfaces[self.tun_name]["idx"]
            self.cmd_run(f'route delete 0.0.0.0 mask 0.0.0.0 if {iface_id}')
        except KeyError:
            pass

        self.cmd_run(
            f'route delete {self.socks_ext} mask 255.255.255.255 {self.gateway_ip} metric 1 if {self.def_iface_id}'
        )

        if not self.tun_proc: return

        try:
            os.kill(self.tun_proc.pid, signal.SIGTERM)
            self.tun_proc = None
        except PermissionError:
            pass


if __name__ == "__main__":
    try:
        tunnel = Tun2Socks()
        tunnel.start()
    except KeyboardInterrupt:
        tunnel.stop()
