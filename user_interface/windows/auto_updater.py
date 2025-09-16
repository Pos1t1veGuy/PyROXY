from typing import *
import requests as rq
import subprocess
import sys


REPO_URL = 'https://api.github.com/repos/Pos1t1veGuy/PyROXY'


def get_windows_zip_version(repo_url: str) -> Tuple[str, str]:
    resp = rq.get(f'{repo_url}/releases')
    resp.raise_for_status()
    releases_json = resp.json()

    commercial_release = next((release for release in releases_json if release['tag_name'] == 'commercial'), None)
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
        [client_path, "--version"],
        capture_output=True,
        text=True
    ).stdout.strip()

def download_file(url: str, dest: Optional[str] = None):
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


if __name__ == '__main__':
    try:
        repo_version, win_zip_url = get_windows_zip_version(REPO_URL)
        current_version = get_client_version("client.exe" if not "--py" in sys.argv else "client.py")

        if repo_version != current_version:
            agreement = input('[+] PyROXY client is outdated and needs to be updated. Leaving the current version may'
                              ' cause compatibility issues. Skip updating?\nY/N: ')

            if agreement.lower() in ['y', 'yes']:
                print('[-] Cancelled by user')
            else:
                download_file(win_zip_url)
                print(f'\n[+] Download finished')

    except Exception as ex:
        print(f'[e] {ex}')