from typing import *
import os, sys
import ctypes
import platform
import subprocess
import zipfile
import requests as rq
import time
from pathlib import Path


client = 'client.exe'
updater = 'updater.exe'
REPO_URL = 'https://api.github.com/repos/Pos1t1veGuy/PyROXY'
BASE_DIR = Path(sys.executable if getattr(sys, 'frozen', False) else __file__).parent



def is_admin() -> bool:
    if platform.system() == "Windows":
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False
    else:
        return os.geteuid() == 0


def parse_version(v: str) -> tuple[int, ...]:
    v = v.lstrip('v').split('-')[0]
    parts = [int(p) for p in v.split('.') if p.isdigit()]
    return tuple(parts)

def rq_get_with_retry(url: str, retries: int = 3, delay: int = 2) -> rq.Response:
    for attempt in range(retries):
        try:
            resp = rq.get(url, timeout=(10, 15))
            resp.raise_for_status()
            return resp
        except rq.exceptions.RequestException as e:
            print(f"[!] Attempt {attempt + 1}/{retries} failed: {e}")
            if attempt < retries - 1:
                time.sleep(delay)
    raise ConnectionError(f"Failed to fetch {url} after {retries} attempts")

def get_windows_zip_version(repo_url: str) -> Tuple[str, str]:
    resp = rq_get_with_retry(f'{repo_url}/releases')
    resp.raise_for_status()
    releases_json = resp.json()

    commercial_release = next((release for release in releases_json if release['tag_name'] == 'commercial-bins'), None)
    if commercial_release:
        assets = commercial_release.get('assets')
        if assets:
            try:
                win_zip = next(a for a in assets if a["name"].startswith("windows.") and a["name"].endswith('.zip'))
                zip_version = win_zip['name'].split('windows.')[1].split('.zip')[0]
                zip_url = win_zip['browser_download_url']

                return zip_version, zip_url
            except (KeyError, StopIteration):
                raise Exception('Invalid json received from github')
        else:
            raise Exception('Invalid github release url: can not find assets')
    else:
        raise Exception('Invalid github release url: can not find "commercial" release')

def get_client_version(client_path: str) -> str:
    return subprocess.run(
        client_path.split() + ["--version"],
        capture_output=True,
        text=True
    ).stdout.strip()

def download_file(url: str, dest: Optional[str] = None) -> str:
    if dest is None:
        dest = os.path.basename(url)

    print('[+] Updating...')
    with rq.get(url, stream=True) as r:
        r.raise_for_status()
        total_size = int(r.headers.get('content-length', 0))
        downloaded = 0

        with open(dest, 'wb') as f:
            for chunk in r.iter_content(chunk_size=8192):
                if chunk:
                    f.write(chunk)
                    downloaded += len(chunk)
                    done = int(50 * downloaded / total_size) if total_size else 0
                    sys.stdout.write(f'\r[+] Downloading: [{"█" * done}{"." * (50 - done)}] {downloaded}/{total_size} bytes')
                    sys.stdout.flush()
    return dest


def check_updates():
    print(f'[+] Checking updates...')
    try:
        repo_version, win_zip_url = get_windows_zip_version(REPO_URL)
    except ConnectionError:
        print('[w] Github service is unavailable, unable to check for updates')
        return

    current_version = get_client_version("client.exe" if not "--py" in sys.argv else "python client.py")

    if parse_version(repo_version) > parse_version(current_version):
        agreement = input(
            '[+] PyROXY client is outdated and needs to be updated. Leaving the current version may'
            f' cause compatibility issues.\n\n{current_version} -> {repo_version}\n'
            '\nSkip updating?\nY/N: ')

        if agreement.lower() in ['y', 'yes', 'н']:
            print('[-] Cancelled by user')
        else:
            zip_path = download_file(win_zip_url)
            with zipfile.ZipFile(BASE_DIR / zip_path, 'r') as zip_ref:
                zip_ref.extract(updater, BASE_DIR)
            print(f'\n[+] Download finished')
            subprocess.Popen([str(BASE_DIR / updater), str(BASE_DIR / zip_path)])
            sys.exit(0)
    else:
        print(f'[+] Running PyROXY client {current_version} - latest')


if __name__ == '__main__':
    try:
        if not is_admin():
            raise Exception('Administrator privileges required. Press ENTER to close...')
            sys.exit(1)

        if not '--update_skip' in sys.argv:
            check_updates()
        if '--py' in sys.argv:
            tunnel = Path(__file__).parent.parent.parent / 'tunnel'
            client = f'python client.py --tun2socks_path {tunnel / "tun2socks.exe"}'

        if os.path.isfile('profile.pyroxy'):
            print('[+] Running with profile config...')
            parameters = ' --'.join(open('profile.pyroxy', 'r').read().split('\n'))
            os.system(
                f'{client} --{parameters}' + ' '.join(sys.argv[1:]).replace('--py', '').replace('--update_skip', '')
            )
            input('[+] Press ENTER to exit. ')
        else:
            raise Exception('profile config not found, looking for a "profile.proxy" file. Press ENTER to close the program...')

    except KeyboardInterrupt:
        pass
    except Exception as ex:
        try:
            input(f'[e] {ex}')
        except KeyboardInterrupt:
            pass