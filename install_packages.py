import sys, subprocess, os

if os.path.isfile('requirements.txt'):
    subprocess.run(["pip", "install", "-r", 'requirements.txt'], check=True)

modules = ['ciphers', 'wrappers', 'tunnel', 'user_interface']
for name in modules:
    path = f"./{name}/requirements.txt"
    subprocess.run(["pip", "install", "-r", path], check=True)