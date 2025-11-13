import sys, subprocess, os

if os.path.isfile('requirements.txt'):
    subprocess.run(["pip", "install", "-r", 'requirements.txt'], check=True)

modules = ['ciphers', 'wrappers', 'db_handlers', 'tunnel', 'user_interface']
for name in modules:
    if os.path.isfile(f"./{name}/requirements.txt"):
        path = f"./{name}/requirements.txt"
        print(f'[+] Found {name} package')
        subprocess.run(["pip", "install", "-r", path], check=True)
        print(f'[+] {name} package installed')
    else:
        print(f'[!] Not found {name} package')