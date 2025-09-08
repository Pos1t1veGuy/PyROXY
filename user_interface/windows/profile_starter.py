import os, sys
import ctypes
import platform
from pathlib import Path


target = 'client.exe'


def is_admin():
    if platform.system() == "Windows":
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False
    else:
        return os.geteuid() == 0

try:
    if not is_admin():
        input('[e] Administrator privileges required')
        sys.exit(1)

    if '--py' in sys.argv:
        tunnel = Path(__file__).parent.parent.parent / 'tunnel'
        target = f'python client.py --tun2socks_path {tunnel / "tun2socks.exe"}'

    if os.path.isfile('profile.pyroxy'):
        print('[+] running with profile config...')
        parameters = ' --'.join(open('profile.pyroxy', 'r').read().split('\n'))
        os.system(
            f'{target} --{parameters}' + ' '.join(sys.argv[1:]).replace('--py', '')
        )
        input('[+] Press ENTER to exit. ')
    else:
        input('[e] profile config not found, looking for a "profile.proxy" file. Press ENTER to close the program...')

except KeyboardInterrupt:
    pass